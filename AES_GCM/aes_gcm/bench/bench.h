#ifndef BENCH_H
#define BENCH_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cpucycles.h>

#include "c_aesni/key_schedule.h"
#include "c_ref/gcm.h"
#include "print.h"

/*
	Export Jasmin functions
*/
extern void aes128_gcm_encrypt_export(uint8_t* in_ptr, uint8_t* ivec_ptr, uint8_t* addt_ptr,
                                      uint8_t** out_ptr, uint64_t* sizes, uint8_t* key_ptr);
extern int aes128_gcm_decrypt_export(uint8_t** in_ptr, uint8_t* ivec_ptr, uint8_t* addt_ptr,
                                     uint8_t* out_ptr, uint64_t* sizes, uint8_t* key_ptr);

/*
	Export C AES-NI functions
*/
extern void AES_128_Key_Expansion(const uint8_t *userkey, AES_KEY *key);
extern void AES_GCM_encrypt(const unsigned char *in, unsigned char *out, const unsigned char* addt, const unsigned char* ivec,
                            unsigned char *tag, int nbytes, int abytes, int ibytes, const unsigned char* key, int nr);
extern int AES_GCM_decrypt(const unsigned char *in, unsigned char *out, const unsigned char* addt, const unsigned char* ivec,
                           unsigned char *tag, int nbytes, int abytes, int ibytes, const unsigned char* key, int nr);

/*
	Export C Ref functions
*/
extern int aes_gcm_encrypt(unsigned char* output, const unsigned char* input, int input_length, const unsigned char* key, const size_t key_len, const unsigned char * iv, const size_t iv_len, const unsigned char * aad, const size_t aad_len, unsigned char * tag, const size_t tag_len);
extern int aes_gcm_decrypt(unsigned char* output, const unsigned char* input, int input_length, const unsigned char* key, const size_t key_len, const unsigned char * iv, const size_t iv_len, const unsigned char * aad, const size_t aad_len, unsigned char * tag, const size_t tag_len);

#define TIMINGS 100000
#define OP 6
#define C_REF_ENC 0
#define C_REF_DEC 1
#define C_AESNI_ENC 2
#define C_AESNI_DEC 3
#define JASMIN_ENC 4
#define JASMIN_DEC 5

#if defined( BENCH1 )
    #define KEY_LEN 16
    #define IN_LEN 86
    #define AAD_LEN 25
    #define IVEC_LEN 12
    #define TAG_LEN 16
#elif defined( BENCH2 )
    #define KEY_LEN 16
    #define IN_LEN 1224
    #define AAD_LEN 40
    #define IVEC_LEN 12
    #define TAG_LEN 16
#endif

/*
	Test functions
*/
void test_all_cpu();

#endif
