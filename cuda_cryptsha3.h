/*
* This software is Copyright (c) 2013 Taylor Nelson, Dj Mitchell
* With inspiration from Lukas Odiazabal (see cuda md5 sources)
* and it is hereby released to the general public under the following terms:
* Redistribution and use in source and binary forms, with or without modification, are permitted.
*/
#ifndef _CUDA_CRYPTSHA3_H
#define _CUDA_CRYPTSHA3_H
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>
#include "common.h"

#define uint32_t unsigned int
#define uint8_t unsigned char

#define BLOCKS			28*3
#define THREADS 		256
#define KEYS_PER_CRYPT		BLOCKS*THREADS
#define PLAINTEXT_LENGTH	15
//^ max plain length

typedef struct {
	uint32_t hash[4];	//hash that we are looking for
	uint8_t length;   //salt length
	char salt[8];  //we don't really know the salt/salt prefix
	char prefix;		// 'a' when $apr1$ or '1' when $1$
} crypt_sha3_salt;

typedef struct {
	uint8_t length;
	uint8_t v[PLAINTEXT_LENGTH];
} crypt_sha3_password;

typedef struct {
	  char cracked;
} crypt_sha3_crack;

typedef struct __attribute__((__aligned__(4))){
	uint8_t buffer[64];
} sha3_ctx ;


//This is made up
static const char sha3_salt_prefix[] = "$sha3$";
//bellow is md5 prefix, I don't know any defined prefix for sha3 salts
//static const char apr1_salt_prefix[] = "$apr1$";


/********* Sha3 Rotation/Bit Macros  ***********/

/**
 * Returns the index of Keccak state word state[x][y] for evaluation eval.
 */
#define index(x,y) (((y)*5+(x))*NT+eval)

/**
 * Pack two 32-bit words a and b into a 64-bit long word x, with a in the most
 * significant position and b in the least significant position, then reverse
 * the byte order of x.
 */
#define packAndReverseBytes(x,a,b) \
	x = (((u_int64_t) b) << 32) | ((u_int64_t) a); \
	x = ((x & 0x0000FFFF0000FFFF) << 16) | ((x & 0xFFFF0000FFFF0000) >> 16); \
	x = ((x & 0x00FF00FF00FF00FF) <<  8) | ((x & 0xFF00FF00FF00FF00) >>  8)

/**
 * Reverse the byte order of 64-bit long word x, then unpack x into two 32-bit
 * words a and b, with a in the most significant position and b in the least
 * significant position.
 */
#define reverseBytesAndUnpack(x,a,b) \
	x = ((x & 0x00FF00FF00FF00FF) <<  8) | ((x & 0xFF00FF00FF00FF00) >>  8); \
	x = ((x & 0x0000FFFF0000FFFF) << 16) | ((x & 0xFFFF0000FFFF0000) >> 16); \
	b = (u_int32_t) (x >> 32); \
	a = (u_int32_t) x

/**
 * Returns x rotated y positions upwards.
 */
#define ROT(x,y) \
	(((x) << (y)) | ((x) >> (64 - (y))))

/**
 * Returns the next state for LFSR with state x.
 */
#define NEXT_STATE(x) \
	((x & 0x80) ? ((x << 1) ^ 0x171) : (x << 1))

/******************************************************/

/*********************** Sha3 Constants ***************/

#define NT 64
#define IB 256
#define OB 256
#define IW ((IB + 31)/32)
#define OW ((OB + 31)/32)

#endif
