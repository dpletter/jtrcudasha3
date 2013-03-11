/*
* This software is Copyright (c) 2013 Taylor Nelson/DJ Mitchell <eipeace2u at gmail dot com> <dj_trumpet at hotmail dot com> with inspiration from Lukas Odzioba's md5 implementaiton of the cuda format in john the ripper
* and it is hereby released to the general public under the following terms:
* Redistribution and use in source and binary forms, with or without modification, are permitted.
*/

#include <string.h>
#include <unistd.h>
#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "cuda_common.h"
#include "cuda_cryptsha3.h"

#define FORMAT_LABEL		"sha3crypt-cuda"
#define FORMAT_NAME		"sha3crypt"

#define ALGORITHM_NAME		"CUDA"

#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1

#define BINARY_SIZE		16
#define SALT_SIZE		(sizeof(crypt_md5_salt))
#define MIN_KEYS_PER_CRYPT	KEYS_PER_CRYPT
#define MAX_KEYS_PER_CRYPT	KEYS_PER_CRYPT

void sha3_crypt_gpu(crypt_sha3_password *, crypt_sha3_crack *, crypt_sha3_salt *);

static crypt_sha3_password *inbuffer;			/** plaintext ciphertexts **/
static crypt_sha3_crack *outbuffer;			/** cracked or no **/
static crypt_sha3_salt host_salt;			/** salt **/
static int any_cracked;

//#define CUDA_DEBUG

/* Sha3 test vectors go here */
/* Vectors from: 
http://keccak.noekeon.org/files.html
But they use KAT generation/their own?
http://en.wikipedia.org/wiki/SHA-3
static vectors ^
*/
static struct fmt_tests tests[] = {
	{"$1$Btiy90iG$bGn4vzF3g1rIVGZ5odGIp/", "qwerty"},
	{NULL}
};

static void cleanup()
{
	free(inbuffer);
	free(outbuffer);
}

static void init(struct fmt_main *self)
{
	///Alocate memory for hashes and passwords
	inbuffer =
	    (crypt_sha3_password *) calloc(MAX_KEYS_PER_CRYPT,
	    sizeof(crypt_sha3_password));
	outbuffer =
	    (crypt_sha3_crack *) calloc(MAX_KEYS_PER_CRYPT,
	    sizeof(crypt_sha3_crack));
	check_mem_allocation(inbuffer, outbuffer);
	atexit(cleanup);
	///Initialize CUDA
	cuda_init(cuda_gpu_id);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	uint8_t i, len = strlen(ciphertext), prefix = 0;
	char *p;

	if (strncmp(ciphertext, sha3_salt_prefix, strlen(md5_salt_prefix)) == 0)
		prefix |= 1;
	//XXX Add null prefix tesT?
	if (strncmp(ciphertext, apr1_salt_prefix,
		strlen(apr1_salt_prefix)) == 0)
		prefix |= 2;
	if (prefix == 0)
		return 0;
	p = strrchr(ciphertext, '$');
	if (p == NULL)
		return 0;
	for (i = p - ciphertext + 1; i < len; i++) {
		uint8_t z = ARCH_INDEX(ciphertext[i]);
		if (ARCH_INDEX(atoi64[z]) == 0x7f)
			return 0;
	}
	if (len - (p - ciphertext + 1) != 22)
		return 0;
	return 1;
};

//No changes needed, hash independent
static int findb64(char c)
{
	int ret = ARCH_INDEX(atoi64[(uint8_t) c]);
	return ret != 0x7f ? ret : 0;
}

//hash indepdendent
static void to_binary(char *crypt, char *alt)
{

#define _24bit_from_b64(I,B2,B1,B0) \
  {\
      uint8_t c1,c2,c3,c4,b0,b1,b2;\
      uint32_t w;\
      c1=findb64(crypt[I+0]);\
      c2=findb64(crypt[I+1]);\
      c3=findb64(crypt[I+2]);\
      c4=findb64(crypt[I+3]);\
      w=c4<<18|c3<<12|c2<<6|c1;\
      b2=w&0xff;w>>=8;\
      b1=w&0xff;w>>=8;\
      b0=w&0xff;w>>=8;\
      alt[B2]=b0;\
      alt[B1]=b1;\
      alt[B0]=b2;\
  }
	uint32_t w;
	_24bit_from_b64(0, 0, 6, 12);
	_24bit_from_b64(4, 1, 7, 13);
	_24bit_from_b64(8, 2, 8, 14);
	_24bit_from_b64(12, 3, 9, 15);
	_24bit_from_b64(16, 4, 10, 5);
	w = findb64(crypt[21]) << 6 | findb64(crypt[20]) << 0;
	alt[11] = (w & 0xff);
}

//hash independent
static void *binary(char *ciphertext)
{
	static char b[BINARY_SIZE];
	char *p;
	memset(b, 0, BINARY_SIZE);
	p = strrchr(ciphertext, '$') + 1;
	to_binary(p, b);
	return (void *) b;
}


//sha3salt needs to be figured out CUDA_DEBUG
static void *salt(char *ciphertext)
{
#ifdef CUDA_DEBUG
	printf("salt(%s)\n", ciphertext);
#endif
	static crypt_sha3_salt ret;
	uint8_t i, *pos = (uint8_t *) ciphertext, *end;
	char *p,*dest = ret.salt;
	if (strncmp(ciphertext, sha3_salt_prefix, strlen(sha3_salt_prefix)) == 0) {
		pos += strlen(md5_salt_prefix);
		ret.prefix = '1';
	}
	//XXX other salt prefix needs to be null?/removed?
	if (strncmp(ciphertext, apr1_salt_prefix,
		strlen(apr1_salt_prefix)) == 0) {
		pos += strlen(apr1_salt_prefix);
		ret.prefix = 'a';
	}
	end = pos;
	for (i = 0; i < 8 && *end != '$'; i++, end++);
	while (pos != end)
		*dest++ = *pos++;
	ret.length = i;
	p = strrchr(ciphertext, '$') + 1;
	to_binary(p,(char*) ret.hash);
#ifdef CUDA_DEBUG
	puts("salted:");
	uint32_t *t=ret.hash;
	for(i=0;i<4;i++)
	  printf("%08x ",t[i]);
	puts("");
#endif
	return (void *) &ret;
}

static void set_salt(void *salt)
{
	memcpy(&host_salt, salt, sizeof(crypt_sha3_salt));
	any_cracked = 0;
}

//with the right constants this should be hash independent
static void set_key(char *key, int index)
{

#ifdef CUDA_DEBUG
	printf("set_key(%d,%s)\n", index, key);
#endif
	uint32_t len = strlen(key);
	inbuffer[index].length = len;
	memcpy((char *) inbuffer[index].v, key, len);
}

static char *get_key(int index)
{
	static char ret[PLAINTEXT_LENGTH + 1];
	memcpy(ret, inbuffer[index].v, PLAINTEXT_LENGTH);
	ret[inbuffer[index].length] = '\0';
	return ret;
}

static void crypt_all(int count)
{
	int i;
	if (any_cracked) {
		memset(outbuffer, 0, sizeof(crypt_sha3_crack) * KEYS_PER_CRYPT);
		any_cracked = 0;
	}
	sha3_crypt_gpu(inbuffer, outbuffer, &host_salt);
	for (i = 0; i < count; i++) {
		any_cracked|=outbuffer[i].cracked;
	}
#ifdef CUDA_DEBUG
	printf("crypt_all(%d)\n", count);
	printf("any_cracked=%d\n",any_cracked);
#endif
}

/* Comparison functions are hash independent */
static int cmp_all(void *binary, int count)
{
	return any_cracked;
}

static int cmp_one(void *binary, int index)
{
	return outbuffer[index].cracked;
}

static int cmp_exact(char *source, int index)
{
	return outbuffer[index].cracked;
}

/* This is the format structure for importation in 
   john.c, must be correct for this to work */
struct fmt_main fmt_cuda_cryptsha3 = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		SALT_SIZE,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT,
		tests
	}, {
		init,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		binary,
		salt,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		set_salt,
		set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
			fmt_default_get_hash
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};
