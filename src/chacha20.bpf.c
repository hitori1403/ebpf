#pragma once

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#define min(a, b)  ((a) < (b) ? (a) : (b))

#define ROTL(a, b) (((a) << (b)) | ((a) >> (32 - (b))))

#define QR(a, b, c, d)                                                                     \
	(a += b, d ^= a, d = ROTL(d, 16), c += d, b ^= c, b = ROTL(b, 12), a += b, d ^= a, \
	 d = ROTL(d, 8), c += d, b ^= c, b = ROTL(b, 7))

#define ROUNDS		    20
#define CHACHA20_BLOCK_SIZE 64

struct chacha20_ctx {
	u32 state[16];
	u8 *data;
	u64 data_sz;
	u8 skip;
};

unsigned char buf[CHACHA20_BLOCK_SIZE];
unsigned char keystream[CHACHA20_BLOCK_SIZE];

static int chacha20_block(u32 out[16], u32 const in[16])
{
	u32 x[16];

	for (int i = 0; i < 16; ++i)
		x[i] = in[i];

	for (int i = 0; i < ROUNDS; i += 2) {
		QR(x[0], x[4], x[8], x[12]);
		QR(x[1], x[5], x[9], x[13]);
		QR(x[2], x[6], x[10], x[14]);
		QR(x[3], x[7], x[11], x[15]);

		QR(x[0], x[5], x[10], x[15]);
		QR(x[1], x[6], x[11], x[12]);
		QR(x[2], x[7], x[8], x[13]);
		QR(x[3], x[4], x[9], x[14]);
	}

	for (int i = 0; i < 16; ++i)
		out[i] = x[i] + in[i];

	return 0;
}

static void chacha20_init(u32 state[16], u8 key[32], u8 nonce[12], u32 counter)
{
	state[0] = 0x61707865;
	state[1] = 0x3320646E;
	state[2] = 0x79622D32;
	state[3] = 0x6B206574;

	for (int i = 0; i < 8; ++i)
		state[4 + i] = ((u32 *)key)[i];

	state[12] = counter;

	for (int i = 0; i < 3; ++i)
		state[13 + i] = ((u32 *)nonce)[i];
}

static int encrypt_block_cb(u32 blk_idx, struct chacha20_ctx *ctx)
{
	if (ctx->skip >= CHACHA20_BLOCK_SIZE)
		return 0;

	u64 len_to_cur_blk = blk_idx * CHACHA20_BLOCK_SIZE;
	if (ctx->data_sz <= len_to_cur_blk)
		return 0;

	u8 cur_blk_sz = min(ctx->data_sz - len_to_cur_blk, CHACHA20_BLOCK_SIZE - ctx->skip);

	bpf_probe_read_user(buf, cur_blk_sz, ctx->data + len_to_cur_blk);

	chacha20_block((u32 *)keystream, ctx->state);

	for (int i = 0; i < cur_blk_sz; ++i) {
		// useless check to bypass verifier
		u8 j = i + ctx->skip;
		if (j >= CHACHA20_BLOCK_SIZE)
			return 0;

		buf[i] ^= keystream[j];
	}

	/* bpf_probe_write_user(ctx->data + len_to_cur_blk, buf, cur_block_sz); */
	if (cur_blk_sz == CHACHA20_BLOCK_SIZE) {
		bpf_probe_write_user(ctx->data + len_to_cur_blk, buf, CHACHA20_BLOCK_SIZE);
	} else {
		/* brainrot trick to work around bpf_probe_write_user only accepting a constant size */
		for (int i = 0; i < cur_blk_sz; ++i)
			bpf_probe_write_user(ctx->data + len_to_cur_blk + i, buf + i, 1);
	}

	++ctx->state[12];

	if (ctx->skip) {
		ctx->data -= ctx->skip;
		ctx->data_sz += ctx->skip;
		ctx->skip = 0;
	}

	return 0;
}

static int chacha20_docrypt_user(u8 *data, u32 size, u8 key[32], u8 nonce[12], u32 counter, u8 skip)
{
	if (skip >= CHACHA20_BLOCK_SIZE)
		return 0;

	struct chacha20_ctx ctx;

	ctx.data = data;
	ctx.data_sz = size;
	ctx.skip = skip;

	chacha20_init(ctx.state, key, nonce, counter);

	u32 blocks = (ctx.data_sz + 63) >> 6;
	if (skip)
		++blocks;

	bpf_loop(blocks, (void *)encrypt_block_cb, &ctx, 0);

	return 0;
}
