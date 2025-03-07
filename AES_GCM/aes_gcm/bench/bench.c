#include "bench.h"

extern uint8_t* __jasmin_syscall_randombytes__(uint8_t* x, uint64_t xlen);

void get_random_value(uint8_t *arr, uint64_t arr_len)
{
    uint8_t bytes[arr_len];
    __jasmin_syscall_randombytes__(bytes, arr_len);
    memcpy(arr, bytes, arr_len);
}

void test_all_cpu()
{
    int i, res;
    uint64_t t1, t2;
    uint64_t values[OP][TIMINGS];

    // Jasmin arrays
    uint8_t j_key[KEY_LEN], j_ivec[IVEC_LEN], j_aad[AAD_LEN], j_in[IN_LEN], j_out[IN_LEN], j_tag[TAG_LEN];
    uint8_t* j_output[2] = {j_out, j_tag};
    uint64_t j_sizes[4] = {IN_LEN, AAD_LEN, IVEC_LEN, TAG_LEN};

    // C AES-NI arrays
    unsigned char i_in[IN_LEN], i_out[IN_LEN], i_aad[AAD_LEN], i_ivec[IVEC_LEN], i_tag[TAG_LEN], i_key[KEY_LEN];

    // C Ref arrays
    unsigned char c_out[IN_LEN], c_in[IN_LEN], c_key[KEY_LEN], c_iv[IVEC_LEN], c_aad[AAD_LEN], c_tag[TAG_LEN];

    // WARMUP ??

    // C Ref implementation benchmarking
    for (i = 0; i < TIMINGS; i++) {
        // Generate random values
        get_random_value(c_key, KEY_LEN);
        get_random_value(c_iv, IVEC_LEN);
        get_random_value(c_aad, AAD_LEN);
        get_random_value(c_in, IN_LEN);

        // C Ref encrypt
        t1 = cpucycles();
        gcm_initialize();
        res = aes_gcm_encrypt(c_out, c_in, IN_LEN, c_key, KEY_LEN, c_iv, IVEC_LEN, c_aad, AAD_LEN, c_tag, TAG_LEN);
        t2 = cpucycles();
        values[C_REF_ENC][i] = t2 - t1;

        // C Ref decrypt
        t1 = cpucycles();
        gcm_initialize();
        res = aes_gcm_decrypt(c_in, c_out, IN_LEN, c_key, KEY_LEN, c_iv, IVEC_LEN, c_aad, AAD_LEN, c_tag, TAG_LEN);
        t2 = cpucycles();
        values[C_REF_DEC][i] = t2 - t1;
    }

    // C AES-NI implementation benchmarking
    AES_KEY aes_key;
    for (i = 0; i < TIMINGS; i++) {
        // Generate random values
        get_random_value(i_key, KEY_LEN);
        get_random_value(i_ivec, IVEC_LEN);
        get_random_value(i_aad, AAD_LEN);
        get_random_value(i_in, IN_LEN);

        // C AES-NI encrypt
        t1 = cpucycles();
        AES_128_Key_Expansion(i_key, &aes_key);
        AES_GCM_encrypt(i_in, i_out, i_aad, i_ivec, (unsigned char*)&i_tag, IN_LEN, AAD_LEN, IVEC_LEN, aes_key.KEY, aes_key.nr);
        t2 = cpucycles();
        values[C_AESNI_ENC][i] = t2 - t1;

        // C AES-NI decrypt
        t1 = cpucycles();
        AES_128_Key_Expansion(i_key, &aes_key);
        res = AES_GCM_decrypt(i_out, i_in, i_aad, i_ivec, (unsigned char*)&i_tag, IN_LEN, AAD_LEN, IVEC_LEN, aes_key.KEY, aes_key.nr);
        t2 = cpucycles();
        values[C_AESNI_DEC][i] = t2 - t1;
    }
    
    // Jasmin implementation benchmarking
    for (i = 0; i < TIMINGS; i++) {
        // Generate random values
        get_random_value(j_key, KEY_LEN);
        get_random_value(j_ivec, IVEC_LEN);
        get_random_value(j_aad, AAD_LEN);
        get_random_value(j_in, IN_LEN);

        // Jasmin encrypt
        t1 = cpucycles();
        aes128_gcm_encrypt_export(j_in, j_ivec, j_aad, j_output, j_sizes, j_key);
        t2 = cpucycles();
        values[JASMIN_ENC][i] = t2 - t1;

        // Jasmin decrypt
        t1 = cpucycles();
        res = aes128_gcm_decrypt_export(j_output, j_ivec, j_aad, j_in, j_sizes, j_key);
        t2 = cpucycles();
        values[JASMIN_DEC][i] = t2 - t1;
    }

    // Print results
    print_results((uint64_t*) values);
}

int main( int argc, char** argv )
{
    test_all_cpu();
}
