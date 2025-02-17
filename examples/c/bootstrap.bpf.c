// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "bootstrap.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1<<16);
	__type(key, pid_t);
	__type(value, s32);
} fd_count SEC(".maps");

/**
 * @brief Increment the fd_count by a given value 
 */
void handle_open(int increment) {
	u64 id = bpf_get_current_pid_tgid();
	pid_t pid = id >> 32;

	void *elem = bpf_map_lookup_elem(&fd_count, &pid);
	s32 value = 0;
	if (elem) {
		value = *((s32 *)elem);
		value += increment;
	} else {
		value = increment;
	}
	bpf_map_update_elem(&fd_count, &pid, &value, BPF_ANY);
}

/**
 * @brief Increment the counter on open and openat.
 * Please note that these syscalls don't cover ALL cases
 */
SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint__syscalls__sys_enter_openat(struct trace_event_raw_sys_enter *ctx) {
	handle_open(1);
	return 0;
}

/**
 * @brief Increment the counter on open and openat
 * Please note that these syscalls don't cover ALL cases
 */
SEC("tracepoint/syscalls/sys_enter_open")
int tracepoint__syscalls__sys_enter_open(struct trace_event_raw_sys_enter *ctx) {
	handle_open(1);
	return 0;
}

/**
 * @brief Decrement the counter on close
 */
SEC("tracepoint/syscalls/sys_enter_close")
int tracepoint__syscalls__sys_enter_close(struct trace_event_raw_sys_enter *ctx) {
	handle_open(-1);
	return 0;
}

/**
 * @brief Reset the fd count for a new process
 */
SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx) {
	u64 id = bpf_get_current_pid_tgid();
	pid_t pid = id >> 32;

	s32 value = 2;
	bpf_map_update_elem(&fd_count, &pid, &value, BPF_ANY);

	bpf_printk("Process %d created\n", pid);
	return 0;
}

/**
 * Remove process from the map on exit
 */
SEC("tp/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_exec *ctx) {
	u64 id = bpf_get_current_pid_tgid();
	pid_t pid = id >> 32;

	bpf_map_delete_elem(&fd_count, &pid);

	bpf_printk("Process %d exited\n", pid);
	return 0;
}
