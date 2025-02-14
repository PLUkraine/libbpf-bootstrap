// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <ctype.h>
#include <dirent.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include "bootstrap.h"
#include "bootstrap.skel.h"

struct {
	pid_t pid;
	int32_t cnt;
} typedef pid_cnt;

static const uint32_t SLEEP_SECONDS = 5;
static struct bootstrap_bpf *skel;
static volatile bool exiting = false;
static pid_cnt pid_fd_count[1 << 16];

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return 0;
	/* Uncomment to enable debug logging */
	// return vfprintf(stderr, format, args);
}

/**
 * @brief Exit the main loop and cleanup on UNIX signals SIGTERM and SIGINT
 */
static void sig_handler(int sig)
{
	exiting = true;
}

static bool is_number(const char *s, uint32_t n)
{
	while (*s && n--) {
		if (!isdigit(*(s++))) {
			return false;
		}
	}
	return true;
}

/**
 * @brief Count the number of opened FD by reading /proc
 * @param fd_callback callback for performing an arbitrary action on the per-process FD count
 */
int collect_fd_count(int (*fd_callback)(int pid, int cnt))
{
	char fdpath[300];
	DIR *proc_dir;
	DIR *fd_dir;
	struct dirent *entry;
	struct dirent *fd_entry;
	int pid_cnt;

	if (!(proc_dir = opendir("/proc"))) {
		return -1;
	}

	while ((entry = readdir(proc_dir)) != NULL) {
		int pid = 0;
		int fd_cnt = 0;

		/* Ignore non-number directories */
		if (!is_number(entry->d_name, 256)) {
			continue;
		}
		pid = atoi(entry->d_name);

		/* Open directory that contains all opened FDs */
		snprintf(fdpath, sizeof(fdpath) - 1, "/proc/%d/fd", pid);
		if (!(fd_dir = opendir(fdpath))) {
			continue;
		}

		/* Count files in /proc/<pid>/fd folder */
		++pid_cnt;
		while ((fd_entry = readdir(fd_dir)) != NULL) {
			++fd_cnt;
		}

		/* TODO process error */
		fd_callback(pid, fd_cnt);
		closedir(fd_dir);
	}

	closedir(proc_dir);
	return pid_cnt;
}

/**
 * @brief Get the name of the process by pid
 * 
 * Read /proc/<pid>/comm file and output to name parameter
 */
int get_pid_name(int pid, char *name, int max_len)
{
	char comm_path[32];
	FILE *comm_fd;
	int bytes_read = 0;

	/* Very important to sanitize to prevent runaway strings */
	memset(name, 0, max_len);
	snprintf(comm_path, sizeof(comm_path) - 1, "/proc/%d/comm", pid);
	if ((comm_fd = fopen(comm_path, "r")) != NULL) {
		bytes_read = fread(name, sizeof(char), max_len - 1, comm_fd);
		/* Strip newline at the end of the comm string */
		if (bytes_read && name[bytes_read - 1] == '\n') {
			name[bytes_read - 1] = '\0';
		}
	}
	fclose(comm_fd);
	return bytes_read;
}

/**
 * @brief Callback for the collect_fd_count function. Set the BPF map value.
 */
int set_bpf_counter(int pid, int cnt)
{
	return bpf_map__update_elem(skel->maps.fd_count, &pid, sizeof(pid), &cnt, sizeof(cnt),
				    BPF_ANY);
}

/**
 * @brief Lookup the name of the process and print FD count
 */
int print_pid_fd_count(int pid, int cnt)
{
	char name[256] = {};
	if (!get_pid_name(pid, name, sizeof(name))) {
		return errno;
	}
	return fprintf(stdout, "%d:%s %d\n", pid, name, cnt);
}
/**
 * @brief Compare struct pid_cnt entries by the pid value
 */
int cmp_pidcnt(const void *a, const void *b)
{
	pid_cnt pidcnt1 = *((pid_cnt *)a);
	pid_cnt pidcnt2 = *((pid_cnt *)b);
	if (pidcnt1.pid < pidcnt2.pid)
		return -1;
	else if (pidcnt1.pid > pidcnt2.pid)
		return 1;
	return 0;
}

int main(int argc, char **argv)
{
	int err;

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Load and verify BPF application */
	skel = bootstrap_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* Load & verify BPF programs */
	err = bootstrap_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/* Important: initialize your maps between load and attach! */
	if (collect_fd_count(set_bpf_counter) <= 0) {
		fprintf(stderr, "Failed to set initial BPF map values\n");
	}

	/* Attach tracepoints */
	err = bootstrap_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	/* Main Loop */
	while (!exiting) {
		int cnt = 0;
		pid_t pid;
		pid_t next_pid;
		int32_t fd_cnt;

		printf("\n\nFD Count\n");
		/* Iterate over the BPF map keys */
		err = bpf_map__get_next_key(skel->maps.fd_count, NULL, &next_pid, sizeof(pid));
		while (!err) {
			pid = next_pid;
			/* Get the value of the current BPF key */
			if ((err = bpf_map__lookup_elem(skel->maps.fd_count, &pid, sizeof(pid),
							&fd_cnt, sizeof(fd_cnt), BPF_ANY))) {
				break;
			}
			pid_cnt result = { pid, fd_cnt };
			pid_fd_count[cnt++] = result;

			err = bpf_map__get_next_key(skel->maps.fd_count, &pid, &next_pid,
						    sizeof(pid));
		}
		/* We do expect ENOENT at the end of the iteration */
		if (err == -ENOENT) {
			qsort(pid_fd_count, cnt, sizeof(pid_cnt), cmp_pidcnt);
			for (int i = 0; i < cnt; ++i) {
				print_pid_fd_count(pid_fd_count[i].pid, pid_fd_count[i].cnt);
			}

			fprintf(stdout, "%d processes\n", cnt);
			/* Flush the buffer to guarantee delivery of all strings to the terminal window */
			fflush(stdout);
		} else {
			fprintf(stderr, "Error: %s\n", strerror(errno));
		}

		sleep(SLEEP_SECONDS);
	}

cleanup:
	/* Clean up */
	bootstrap_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}
