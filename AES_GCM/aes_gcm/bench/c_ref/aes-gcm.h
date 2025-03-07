//
//  aes-gcm.h
//  MKo
//
//  Created by Markus Kosmal on 20/11/14.
//
//

#ifndef mko_aes_gcm_h
#define mko_aes_gcm_h

#include "gcm.h"  

int aes_gcm_encrypt(unsigned char* output, const unsigned char* input, int input_length, const unsigned char* key, const size_t key_len, const unsigned char * iv, const size_t iv_len, const unsigned char * aad, const size_t aad_len, unsigned char * tag, const size_t tag_len);

int aes_gcm_decrypt(unsigned char* output, const unsigned char* input, int input_length, const unsigned char* key, const size_t key_len, const unsigned char * iv, const size_t iv_len, const unsigned char * aad, const size_t aad_len, unsigned char * tag, const size_t tag_len);

#endif