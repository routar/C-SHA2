/*
 * Copyright (c) 2013 Arttu Hynninen
 * Licensed under the MIT License. See the LICENSE file for the full text.
 */

#pragma once
#include <stdint.h>

typedef struct _sha256_ctx {
	uint64_t len;
	uint32_t state [8];
	uint8_t buflen;
	uint8_t buffer [64];
} sha256_ctx;

/*
 * Macros for static initialization
 */

#define SHA256_INIT_STATE { \
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, \
	0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 }
	
#define SHA256_INIT_BUFFER { \
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, \
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, \
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, \
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }

#define SHA256_INIT { 0, SHA256_INIT_STATE, 0, SHA256_INIT_BUFFER }

/*
 * Initializes the context.
 */
void sha256_init(sha256_ctx *ctx);

/*
 * Processes the input buffer.
 */
void sha256_process(sha256_ctx *ctx, const uint8_t *data, size_t length);

/*
 * Finalizes and outputs the calculated hash into the buffer.
 */
void sha256_final(sha256_ctx *ctx, uint8_t out [32]);

/*
 * Digests the input buffer and outputs the calculated hash in one function call.
 */
void sha256_simple(const uint8_t *data, size_t length, uint8_t out [32]);
