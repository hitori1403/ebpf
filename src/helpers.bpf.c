#pragma once

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <linux/limits.h>

struct pathcmp_cb_ctx {
	char *s1;
	char *s2;
	u8 result;
};

// the equal case is sufficient
static int pathcmp_cb(u32 i, struct pathcmp_cb_ctx *ctx)
{
	if (i >= PATH_MAX)
		return 1;

	if (ctx->s1[i] != ctx->s2[i]) {
		ctx->result = 1;
		return 1;
	}

	if (!ctx->s1[i]) {
		ctx->result = 0;
		return 1;
	}

	return 0;
}

struct strrev_cb_ctx {
	char *s;
	u16 pos;
	u16 len;
};

static int strrev_cb(u32 idx, struct strrev_cb_ctx *ctx)
{
	u16 left = ctx->pos + idx;
	u16 right = ctx->pos + ctx->len - idx - 1;

	if (left >= PATH_MAX || right >= PATH_MAX)
		return 1;

	u8 tmp = ctx->s[left];
	ctx->s[left] = ctx->s[right];
	ctx->s[right] = tmp;

	return 0;
}

static int get_d_path(char *buf, struct task_struct *task)
{
	char *name;
	u16 buf_len = 0;
	struct dentry *dentry = BPF_CORE_READ(task, mm, exe_file, f_path.dentry);

	for (u32 i = 0; i < PATH_MAX / 2; ++i) {
		bpf_core_read(&name, sizeof(name), &dentry->d_name.name);

		if (buf_len >= PATH_MAX - 1)
			break;

		u16 len = bpf_probe_read_kernel_str(&buf[buf_len], NAME_MAX, name) - 1;

		if (buf_len >= PATH_MAX || buf[buf_len] == '/') {
			buf[buf_len] = 0; // remove last slash
			break;
		}

		struct strrev_cb_ctx cb_ctx = { buf, buf_len, len };
		bpf_loop(len / 2, (void *)strrev_cb, &cb_ctx, 0);

		buf_len += len;

		if (buf_len < PATH_MAX)
			buf[buf_len] = '/';

		++buf_len;

		dentry = BPF_CORE_READ(dentry, d_parent);
	}

	struct strrev_cb_ctx cb_ctx = { buf, 0, buf_len };
	bpf_loop(buf_len / 2, (void *)strrev_cb, &cb_ctx, 0);

	return buf_len;
}

static void log(const char *file, const char *process, char *action, char *operation)
{
	bpf_printk("File %s - Process %s: %s on %s operation", file, process, action, operation);
}
