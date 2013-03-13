/*
* This software is Copyright (c) 2013 Taylor Nelson/DJ Mitchell <eipeace2u at gmail dot com> <dj_trumpet at hotmail dot com> with inspiration from Lukas Odzioba's md5 implementaiton of the cuda format in john the ripper
* and it is hereby released to the general public under the following terms:
* Redistribution and use in source and binary forms, with or without modification, are permitted.
*/

//All the macros and constants
#include "../cuda_cryptsha3.h"

/**
 * cryptoState stores all of the input words, padded using the padding function
 */

__shared__ u_int32_t cryptoState[NT][OW];

/*
 * Keccak state words.
 */
__shared__ u_int64_t state[5*5*NT];

// TODO: Add cuda_init method that will allocate device memory and call the kernel

// This is our padding function that pads with binary digits in the pattern 1(0)*1 until the input is 256 bits
__device__ void padInputWord (u_int32_t eval)
{
	// Pointer to cryptoState word that we need to pad
	u_int32_t *input = &cryptoState[eval][0];

	// TODO: complete padding function
}

__device__ void keccakBlockPermutation (u_int32_t eval)
{
	u_int32_t round, x, y;

	// Temporary storage.
	u_int64_t C[5], D;

	// Linear feedback shift register for generating round constants.
	u_int32_t LFSR = 1;

	// Get pointer to cryptoState for this evaluation.
	u_int32_t *input = &cryptoState[eval][0];
	
	u_int64_t tmp = 0;

	u_int32_t tmp = 0;


	packAndReverseBytes (tmp, input[7], input[6]);
	state[index(0,0)] = tmp;
	packAndReverseBytes (tmp, input[5], input[4]);
	state[index(1,0)] = tmp;
	packAndReverseBytes (tmp, input[3], input[2]);
	state[index(2,0)] = tmp;
	packAndReverseBytes (tmp, input[1], input[0]);
	state[index(3,0)] = tmp;

	// Apply 24-round permutation.
	for (round = 0; round < 24; ++ round)
	{
		// Theta step.
		for (x = 0; x <= 4; ++ x)
		{
			C[x] = state[index(x,0)];
			for (y = 1; y <= 4; ++ y) 
				C[x] ^= state[index(x,y)];
		}
		for (x = 0; x <= 4; ++ x)
		{
			D = C[(x+4)%5] ^ ROT (C[(x+1)%5], 1);
			for (y = 0; y <= 4; ++ y)
			 	state[index(x,y)] ^= D;
		}

		// Rho step.
		// state[index(0,0)] = state[index(0,0)];
		state[index(1,0)] = ROT (state[index(1,0)],  1);
		state[index(0,2)] = ROT (state[index(0,2)],  3);
		state[index(2,1)] = ROT (state[index(2,1)],  6);
		state[index(1,2)] = ROT (state[index(1,2)], 10);
		state[index(2,3)] = ROT (state[index(2,3)], 15);
		state[index(3,3)] = ROT (state[index(3,3)], 21);
		state[index(3,0)] = ROT (state[index(3,0)], 28);
		state[index(0,1)] = ROT (state[index(0,1)], 36);
		state[index(1,3)] = ROT (state[index(1,3)], 45);
		state[index(3,1)] = ROT (state[index(3,1)], 55);
		state[index(1,4)] = ROT (state[index(1,4)],  2);
		state[index(4,4)] = ROT (state[index(4,4)], 14);
		state[index(4,0)] = ROT (state[index(4,0)], 27);
		state[index(0,3)] = ROT (state[index(0,3)], 41);
		state[index(3,4)] = ROT (state[index(3,4)], 56);
		state[index(4,3)] = ROT (state[index(4,3)],  8);
		state[index(3,2)] = ROT (state[index(3,2)], 25);
		state[index(2,2)] = ROT (state[index(2,2)], 43);
		state[index(2,0)] = ROT (state[index(2,0)], 62);
		state[index(0,4)] = ROT (state[index(0,4)], 18);
		state[index(4,2)] = ROT (state[index(4,2)], 39);
		state[index(2,4)] = ROT (state[index(2,4)], 61);
		state[index(4,1)] = ROT (state[index(4,1)], 20);
		state[index(1,1)] = ROT (state[index(1,1)], 44);

		// Pi step.
		// state[index(0,0)] = state[index(0,0)];
		D = state[index(1,3)];
		state[index(1,3)] = state[index(0,1)];
		state[index(0,1)] = state[index(3,0)];
		state[index(3,0)] = state[index(3,3)];
		state[index(3,3)] = state[index(2,3)];
		state[index(2,3)] = state[index(1,2)];
		state[index(1,2)] = state[index(2,1)];
		state[index(2,1)] = state[index(0,2)];
		state[index(0,2)] = state[index(1,0)];
		state[index(1,0)] = state[index(1,1)];
		state[index(1,1)] = state[index(4,1)];
		state[index(4,1)] = state[index(2,4)];
		state[index(2,4)] = state[index(4,2)];
		state[index(4,2)] = state[index(0,4)];
		state[index(0,4)] = state[index(2,0)];
		state[index(2,0)] = state[index(2,2)];
		state[index(2,2)] = state[index(3,2)];
		state[index(3,2)] = state[index(4,3)];
		state[index(4,3)] = state[index(3,4)];
		state[index(3,4)] = state[index(0,3)];
		state[index(0,3)] = state[index(4,0)];
		state[index(4,0)] = state[index(4,4)];
		state[index(4,4)] = state[index(1,4)];
		state[index(1,4)] = state[index(3,1)];
		state[index(3,1)] = D; // state[index(1,3)];

		// Chi step.
		for (y = 0; y <= 4; ++ y)
		{
			for (x = 0; x <= 4; ++ x)
				C[x] = state[index(x,y)] ^ ((~state[index((x+1)%5,y)]) &
					state[index((x+2)%5,y)]);
			for (x = 0; x <= 4; ++ x)
				state[index(x,y)] = C[x];
		}

		// Iota step.
		for (x = 0; x <= 6; ++ x)
		{
			state[index(0,0)] ^= (LFSR & 1ULL) << ((1 << x) - 1);
			LFSR = NEXT_STATE (LFSR);
		}
	}

	// Flip bytes back to Big-endian 32-bit words and put them into input
	tmp = state[index(0,0)];
	reverseBytesAndUnpack (tmp, input[7], input[6]);
	tmp = state[index(1,0)];
	reverseBytesAndUnpack (tmp, input[5], input[4]);
	tmp = state[index(2,0)];
	reverseBytesAndUnpack (tmp, input[3], input[2]);
	tmp = state[index(3,0)];
	reverseBytesAndUnpack (tmp, input[1], input[0]);

}

__global__ void keccakEntry (u_int32_t *devInput, u_int32_t *devOutput, u_int32_t trial, u_int32_t L)
{
	u_int32_t sample, eval;

	// Sample number
	sample = blockIdx.y;  
	sample *= gridDim.x;
	sample += blockIdx.x;
	sample *= blockDim.x;
	sample += threadIdx.x;

	// Proceed only if sample number is in bounds.
	// This is our boundary check
	if (sample < L)
	{
		// Evaluation number within block
		eval = sample % NT; 

		// Read input from devInput
		// We are reading from dictionaries rather than generating random strings
		cryptoState[eval] = &devInput[sample];

		// Use the padding function to pad the input to make it 256 bits
		padInputWord (eval);

		// Set Keccak state to 0 xor message block. Message block = input message
		// (32 bytes) plus padding of 10...01 (104 bytes), total = 136 bytes = 1088
		// bits. Little-endian byte orderin.

		// memset is way cleaner??
		for (y = 0; y < 5; ++ y)
			for (x = 0; x < 5; ++ x)
				state[index(x,y)] = 0;

		// Compute crypto function.
		// Do we even need to pass in the word here? 

		// xor in new state with first word in wordlen
		// for (int ctr = 0; ctr < wordlen; ctr++) 
		// is this index calculation correct?
		keccakBlockPermutation (eval);

			// Store output.
		for (int i = 0; i < OW; ++ i)
			devOutput[sample*OW + i] = cryptoState[eval][i];


	}
}

__host__ void sha3_crypt_gpu (crypt_sha3_password *inBuffer, crypt_sha3_crack *outBuffer, crypt_sha3_salt *host_salt)
{
	HANDLE_ERROR(cudaMemcpyToSymbol(cuda_salt, host_salt, sizeof(crypt_sha3_salt)));

	crypt_sha3_password *dev_inBuffer;
	crypt_sha3_crack *dev_outBuffer;

	size_t inSize = sizeof(crypt_sha3_password) * KEYS_PER_CRYPT;
	size_t outSize = sizeof(crypt_sha3_crack) * KEYS_PER_CRYPT;

	HANDLE_ERROR(cudaMalloc(&dev_inBuffer, inSize));
	HANDLE_ERROR(cudaMalloc(*dev_outBuffer, inSize));
	HANDLE_ERROR(cudaMemcpy(dev_inBuffer, inBuffer, inSize, cudaMemcpyHostToDevice));

	keccakEntry <<< , >>> (dev_inBuffer, dev_outBuffer, 0, 0);

	HANDLE_ERROR(cudaMemcpy(outBuffer, dev_inBuffer, outSize, cudaMemcpyDeviceToHost));

	HANDLE_ERROR(cudaFree(dev_inBuffer));
	HANDLE_ERROR(cudaFree(dev_outBuffer));
}


