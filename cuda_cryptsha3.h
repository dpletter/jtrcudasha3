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
	char salt[8];
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

static const char sha3_salt_prefix[] = "$1$";
//bellow is md5 prefix, I don't know any defined prefix for sha3 salts
//static const char apr1_salt_prefix[] = "$apr1$";


/* PUT SHA3 ROTATION/BIT MACROS BELOW HERE */

/* PUT SHA3 CONSTANTS BELOW HERE */

#endif
