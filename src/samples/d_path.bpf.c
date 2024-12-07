#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <linux/limits.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* char d_path[PATH_MAX + NAME_MAX]; */
char d_path[65536];

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

SEC("tp/syscalls/sys_enter_unlinkat")
int retrieve_d_path(struct trace_event_raw_sys_enter *ctx)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct dentry *dentry = BPF_CORE_READ(task, mm, exe_file, f_path.dentry);

	char *name;

	u16 d_path_len = 0;
	char *p_d_path = p_d_path;

	for (u32 i = 0; i < PATH_MAX / 2; ++i) {
		bpf_core_read(&name, sizeof(name), &dentry->d_name.name);

		if (d_path_len >= PATH_MAX - 1)
			break;

		u16 len = bpf_probe_read_kernel_str(&d_path[d_path_len], NAME_MAX, name);
		--len;

		if (d_path_len >= PATH_MAX || d_path[d_path_len] == '/') {
			d_path[d_path_len] = 0; // remove last slash
			break;
		}

		struct strrev_cb_ctx cb_ctx = { d_path, d_path_len, len };
		bpf_loop(len / 2, (void *)strrev_cb, &cb_ctx, 0);

		d_path_len += len;

		if (d_path_len < PATH_MAX)
			d_path[d_path_len] = '/';

		++d_path_len;

		dentry = BPF_CORE_READ(dentry, d_parent);
	}

	struct strrev_cb_ctx cb_ctx = { d_path, 0, d_path_len };
	bpf_loop(d_path_len / 2, (void *)strrev_cb, &cb_ctx, 0);

	/* bpf_printk("d_path: %s, len: %d", d_path, d_path_len); */

	return 0;
}
