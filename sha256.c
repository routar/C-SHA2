/*
 * Copyright (c) 2013 Arttu Hynninen
 * Licensed under the MIT License. See the LICENSE file for the full text.
 */

#include <stdint.h>

/*
 * Included for memcpy & memset
 */
#include <string.h>

#include "sha256.h"

#define GET_UINT32(b) ( \
	((uint32_t)(b)[0] << 24) | \
	((uint32_t)(b)[1] << 16) | \
	((uint32_t)(b)[2] <<  8) | \
	((uint32_t)(b)[3]))
	
#define PUT_UINT32(dst, x) { \
	(dst)[0] = (x) >> 24; \
	(dst)[1] = (x) >> 16; \
	(dst)[2] = (x) >>  8; \
	(dst)[3] = (x); }

#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

#define S0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ (x >> 3))
#define S1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ (x >> 10))

#define T0(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define T1(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))

#define CH(a, b, c) (((a) & (b)) ^ ((~(a)) & (c)))
#define MAJ(a, b, c) (((a) & (b)) ^ ((a) & (c)) ^ ((b) & (c)))
#define WW(i) (w[i] = w[i - 16] + S0(w[i - 15]) + w[i - 7] + S1(w[i - 2]))

#define ROUND(a, b, c, d, e, f, g, h, k, w) { \
	uint32_t tmp0 = h + T0(e) + CH(e, f, g) + k + w; \
	uint32_t tmp1 = T1(a) + MAJ(a, b, c); \
	h = tmp0 + tmp1; \
	d += tmp0; }

void sha256_init(sha256_ctx *ctx)
{
	sha256_ctx tmp = SHA256_INIT;
	*ctx = tmp;
}

void sha256_chunk(sha256_ctx *ctx, const uint8_t chunk [64])
{
	const uint32_t rk [64] = {
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
		0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
		0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 };
		
	uint32_t w [64];
	uint32_t a, b, c, d, e, f, g, h;
	
	int i;
	
	for (i = 0; i < 16; i++)
		w[i] = GET_UINT32(&chunk[4 * i]);
	
	a = ctx->state[0];
	b = ctx->state[1];
	c = ctx->state[2];
	d = ctx->state[3];
	e = ctx->state[4];
	f = ctx->state[5];
	g = ctx->state[6];
	h = ctx->state[7];
	
	for (i = 0; i < 16; i += 8) {
		ROUND(a, b, c, d, e, f, g, h, rk[i    ], w[i    ]);
		ROUND(h, a, b, c, d, e, f, g, rk[i + 1], w[i + 1]);
		ROUND(g, h, a, b, c, d, e, f, rk[i + 2], w[i + 2]);
		ROUND(f, g, h, a, b, c, d, e, rk[i + 3], w[i + 3]);
		ROUND(e, f, g, h, a, b, c, d, rk[i + 4], w[i + 4]);
		ROUND(d, e, f, g, h, a, b, c, rk[i + 5], w[i + 5]);
		ROUND(c, d, e, f, g, h, a, b, rk[i + 6], w[i + 6]);
		ROUND(b, c, d, e, f, g, h, a, rk[i + 7], w[i + 7]);
	}
	
	for (i = 16; i < 64; i += 8) {
		ROUND(a, b, c, d, e, f, g, h, rk[i    ], WW(i    ));
		ROUND(h, a, b, c, d, e, f, g, rk[i + 1], WW(i + 1));
		ROUND(g, h, a, b, c, d, e, f, rk[i + 2], WW(i + 2));
		ROUND(f, g, h, a, b, c, d, e, rk[i + 3], WW(i + 3));
		ROUND(e, f, g, h, a, b, c, d, rk[i + 4], WW(i + 4));
		ROUND(d, e, f, g, h, a, b, c, rk[i + 5], WW(i + 5));
		ROUND(c, d, e, f, g, h, a, b, rk[i + 6], WW(i + 6));
		ROUND(b, c, d, e, f, g, h, a, rk[i + 7], WW(i + 7));
	}
	
	ctx->state[0] += a;
	ctx->state[1] += b;
	ctx->state[2] += c;
	ctx->state[3] += d;
	ctx->state[4] += e;
	ctx->state[5] += f;
	ctx->state[6] += g;
	ctx->state[7] += h;
}

void sha256_process(sha256_ctx *ctx, const uint8_t *data, size_t length)
{
	ctx->len += length;
		
	if (ctx->buflen != 0 && ctx->buflen + length >= 64) {
		int blen = 64 - ctx->buflen;
		memcpy(ctx->buffer + ctx->buflen, data, blen);
		sha256_chunk(ctx, ctx->buffer);
		data += blen;
		length -= blen;
		ctx->buflen = 0;
	}

	while (length >= 64) {
		sha256_chunk(ctx, data);
		data += 64;
		length -= 64;
	}
	
	if (length) {
		memcpy(ctx->buffer + ctx->buflen, data, length);
		ctx->buflen += length;
	}
}

void sha256_final(sha256_ctx *ctx, uint8_t out [32])
{
	const char fill [56] = {
		0x80, 0, 0, 0, 0, 0, 0, 0,
		   0, 0, 0, 0, 0, 0, 0, 0,
		   0, 0, 0, 0, 0, 0, 0, 0,
		   0, 0, 0, 0, 0, 0, 0, 0,
		   0, 0, 0, 0, 0, 0, 0, 0,
		   0, 0, 0, 0, 0, 0, 0, 0,
		   0, 0, 0, 0, 0, 0, 0, 0 };
	
	uint32_t flen = (ctx->buflen < 56) ? 56 - ctx->buflen : 120 - ctx->buflen;
	uint8_t buf [8];
	uint32_t hi_len = (uint32_t)(ctx->len >> 29);
	uint32_t lo_len = (uint32_t)(ctx->len << 3);
	
	int i;
	
	PUT_UINT32(&buf[0], hi_len);
	PUT_UINT32(&buf[4], lo_len);
	
	sha256_process(ctx, fill, flen);
	sha256_process(ctx, buf, 8);
	
	for (i = 0; i < 8; i++)
		PUT_UINT32(&out[4 * i], ctx->state[i]);
	
	memset(ctx, 0, sizeof(sha256_ctx));
}

void sha256_simple(const uint8_t *data, size_t length, uint8_t out [32])
{
	sha256_ctx ctx = SHA256_INIT;
	sha256_process(&ctx, data, length);
	sha256_final(&ctx, out);
}
