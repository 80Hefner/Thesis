#include <smmintrin.h>
#include <immintrin.h>
#include <wmmintrin.h>
#include <emmintrin.h>
#include <sys/types.h>
#include <stdalign.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

extern void aes128_ctr_encrypt_export(uint8_t* in_ptr,
                                   uint8_t* ivec_ptr,
                                   uint8_t* nonce_ptr,
                                   uint8_t* out_ptr,
                                   uint64_t length,
                                   uint8_t* key_ptr);
extern void aes128_ctr_decrypt_export(uint8_t* in_ptr,
                                   uint8_t* ivec_ptr,
                                   uint8_t* nonce_ptr,
                                   uint8_t* out_ptr,
                                   uint64_t length,
                                   uint8_t* key_ptr);
extern void aes192_ctr_encrypt_export(uint8_t* in_ptr,
                                   uint8_t* ivec_ptr,
                                   uint8_t* nonce_ptr,
                                   uint8_t* out_ptr,
                                   uint64_t length,
                                   uint8_t* key_ptr);
extern void aes192_ctr_decrypt_export(uint8_t* in_ptr,
                                   uint8_t* ivec_ptr,
                                   uint8_t* nonce_ptr,
                                   uint8_t* out_ptr,
                                   uint64_t length,
                                   uint8_t* key_ptr);
extern void aes256_ctr_encrypt_export(uint8_t* in_ptr,
                                   uint8_t* ivec_ptr,
                                   uint8_t* nonce_ptr,
                                   uint8_t* out_ptr,
                                   uint64_t length,
                                   uint8_t* key_ptr);
extern void aes256_ctr_decrypt_export(uint8_t* in_ptr,
                                   uint8_t* ivec_ptr,
                                   uint8_t* nonce_ptr,
                                   uint8_t* out_ptr,
                                   uint64_t length,
                                   uint8_t* key_ptr);

void print_num_arr(uint8_t* arr, int size)
{
    printf("0x");
    for (int i = size-1; i >= 0; i-=2) {
        printf("%02x%02x ", arr[i], arr[i-1]);
    }
    printf("\n");
}

int test_arr(uint8_t* arr1, uint8_t* arr2, int size)
{
    for (int i = 0; i < size; i++) {
        if (arr1[i] != arr2[i])
            return 0;
    }

    return 1;
}

int main( int argc, char** argv )
{
    /*------------------------------------------------------------
                      ⇓ Initialize test vectors ⇓
    ------------------------------------------------------------*/
    // Test vectors from https://www.ietf.org/rfc/rfc3686.txt
    #ifdef TEST1
        #define LENGTH 16   // plaintext size
            // set pointer to AES CTR functions
            void (*aes_ctr_encrypt)(uint8_t*, uint8_t*, uint8_t*, uint8_t*, uint64_t, uint8_t*) = aes128_ctr_encrypt_export;
            void (*aes_ctr_decrypt)(uint8_t*, uint8_t*, uint8_t*, uint8_t*, uint64_t, uint8_t*) = aes128_ctr_decrypt_export;
            // user key
            uint8_t K[16] = {0xae,0x68,0x52,0xf8,0x12,0x10,0x67,0xcc,
                            0x4b,0xf7,0xa5,0x76,0x55,0x77,0xf3,0x9e};
            // initialization vector
            uint8_t IV[8] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
            // nonce
            uint8_t NONCE[4] = {0x00,0x00,0x00,0x30};
            // plaintext
            uint8_t P[LENGTH] = {0x53,0x69,0x6e,0x67,0x6c,0x65,0x20,0x62,
                                0x6c,0x6f,0x63,0x6b,0x20,0x6d,0x73,0x67};
            // expected ciphertext
            uint8_t E_CIPHER[LENGTH] = {0xe4,0x09,0x5d,0x4f,0xb7,0xa7,0xb3,0x79,
                                        0x2d,0x61,0x75,0xa3,0x26,0x13,0x11,0xb8};
    #endif
    #ifdef TEST2
        #define LENGTH 32
            void (*aes_ctr_encrypt)(uint8_t*, uint8_t*, uint8_t*, uint8_t*, uint64_t, uint8_t*) = aes128_ctr_encrypt_export;
            void (*aes_ctr_decrypt)(uint8_t*, uint8_t*, uint8_t*, uint8_t*, uint64_t, uint8_t*) = aes128_ctr_decrypt_export;
            uint8_t K[16] = {0x7e,0x24,0x06,0x78,0x17,0xfa,0xe0,0xd7,
                            0x43,0xd6,0xce,0x1f,0x32,0x53,0x91,0x63};
            uint8_t IV[8] = {0xc0,0x54,0x3b,0x59,0xda,0x48,0xd9,0x0b};
            uint8_t NONCE[4] = {0x00,0x6c,0xb6,0xdb};
            uint8_t P[LENGTH] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                                0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
                                0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
                                0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f};
            uint8_t E_CIPHER[LENGTH] = {0x51,0x04,0xa1,0x06,0x16,0x8a,0x72,0xd9,
                                        0x79,0x0d,0x41,0xee,0x8e,0xda,0xd3,0x88,
                                        0xeb,0x2e,0x1e,0xfc,0x46,0xda,0x57,0xc8,
                                        0xfc,0xe6,0x30,0xdf,0x91,0x41,0xbe,0x28};
    #endif
    #ifdef TEST3
        #define LENGTH 36
            void (*aes_ctr_encrypt)(uint8_t*, uint8_t*, uint8_t*, uint8_t*, uint64_t, uint8_t*) = aes128_ctr_encrypt_export;
            void (*aes_ctr_decrypt)(uint8_t*, uint8_t*, uint8_t*, uint8_t*, uint64_t, uint8_t*) = aes128_ctr_decrypt_export;
            uint8_t K[16] = {0x76,0x91,0xbe,0x03,0x5e,0x50,0x20,0xa8,
                            0xac,0x6e,0x61,0x85,0x29,0xf9,0xa0,0xdc};
            uint8_t IV[8] = {0x27,0x77,0x7f,0x3f,0x4a,0x17,0x86,0xf0};
            uint8_t NONCE[4] = {0x00,0xe0,0x01,0x7b};
            uint8_t P[LENGTH] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                                0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
                                0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
                                0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,
                                0x20,0x21,0x22,0x23};
            uint8_t E_CIPHER[LENGTH] = {0xc1,0xcf,0x48,0xa8,0x9f,0x2f,0xfd,0xd9,
                                        0xcf,0x46,0x52,0xe9,0xef,0xdb,0x72,0xd7,
                                        0x45,0x40,0xa4,0x2b,0xde,0x6d,0x78,0x36,
                                        0xd5,0x9a,0x5c,0xea,0xae,0xf3,0x10,0x53,
                                        0x25,0xb2,0x07,0x2f};
    #endif
    #ifdef TEST4
        #define LENGTH 16
            void (*aes_ctr_encrypt)(uint8_t*, uint8_t*, uint8_t*, uint8_t*, uint64_t, uint8_t*) = aes192_ctr_encrypt_export;
            void (*aes_ctr_decrypt)(uint8_t*, uint8_t*, uint8_t*, uint8_t*, uint64_t, uint8_t*) = aes192_ctr_decrypt_export;
            uint8_t K[24] = {0x16,0xaf,0x5b,0x14,0x5f,0xc9,0xf5,0x79,
                            0xc1,0x75,0xf9,0x3e,0x3b,0xfb,0x0e,0xed,
                            0x86,0x3d,0x06,0xcc,0xfd,0xb7,0x85,0x15};
            uint8_t IV[8] = {0x36,0x73,0x3c,0x14,0x7d,0x6d,0x93,0xcb};
            uint8_t NONCE[4] = {0x00,0x00,0x00,0x48};
            uint8_t P[LENGTH] = {0x53,0x69,0x6e,0x67,0x6c,0x65,0x20,0x62,
                                0x6c,0x6f,0x63,0x6b,0x20,0x6d,0x73,0x67};
            uint8_t E_CIPHER[LENGTH] = {0x4b,0x55,0x38,0x4f,0xe2,0x59,0xc9,0xc8,
                                        0x4e,0x79,0x35,0xa0,0x03,0xcb,0xe9,0x28};
    #endif
    #ifdef TEST5
        #define LENGTH 32
            void (*aes_ctr_encrypt)(uint8_t*, uint8_t*, uint8_t*, uint8_t*, uint64_t, uint8_t*) = aes192_ctr_encrypt_export;
            void (*aes_ctr_decrypt)(uint8_t*, uint8_t*, uint8_t*, uint8_t*, uint64_t, uint8_t*) = aes192_ctr_decrypt_export;
            uint8_t K[24] = {0x7c,0x5c,0xb2,0x40,0x1b,0x3d,0xc3,0x3c,
                            0x19,0xe7,0x34,0x08,0x19,0xe0,0xf6,0x9c,
                            0x67,0x8c,0x3d,0xb8,0xe6,0xf6,0xa9,0x1a};
            uint8_t IV[8] = {0x02,0x0c,0x6e,0xad,0xc2,0xcb,0x50,0x0d};
            uint8_t NONCE[4] = {0x00,0x96,0xb0,0x3b};
            uint8_t P[LENGTH] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                                0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
                                0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
                                0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f};
            uint8_t E_CIPHER[LENGTH] = {0x45,0x32,0x43,0xfc,0x60,0x9b,0x23,0x32,
                                        0x7e,0xdf,0xaa,0xfa,0x71,0x31,0xcd,0x9f,
                                        0x84,0x90,0x70,0x1c,0x5a,0xd4,0xa7,0x9c,
                                        0xfc,0x1f,0xe0,0xff,0x42,0xf4,0xfb,0x00};
    #endif
    #ifdef TEST6
        #define LENGTH 36
            void (*aes_ctr_encrypt)(uint8_t*, uint8_t*, uint8_t*, uint8_t*, uint64_t, uint8_t*) = aes192_ctr_encrypt_export;
            void (*aes_ctr_decrypt)(uint8_t*, uint8_t*, uint8_t*, uint8_t*, uint64_t, uint8_t*) = aes192_ctr_decrypt_export;
            uint8_t K[24] = {0x02,0xbf,0x39,0x1e,0xe8,0xec,0xb1,0x59,
                            0xb9,0x59,0x61,0x7b,0x09,0x65,0x27,0x9b,
                            0xf5,0x9b,0x60,0xa7,0x86,0xd3,0xe0,0xfe};
            uint8_t IV[8] = {0x5c,0xbd,0x60,0x27,0x8d,0xcc,0x09,0x12};
            uint8_t NONCE[4] = {0x00,0x07,0xbd,0xfd};
            uint8_t P[LENGTH] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                                0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
                                0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
                                0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,
                                0x20,0x21,0x22,0x23};
            uint8_t E_CIPHER[LENGTH] = {0x96,0x89,0x3f,0xc5,0x5e,0x5c,0x72,0x2f,
                                        0x54,0x0b,0x7d,0xd1,0xdd,0xf7,0xe7,0x58,
                                        0xd2,0x88,0xbc,0x95,0xc6,0x91,0x65,0x88,
                                        0x45,0x36,0xc8,0x11,0x66,0x2f,0x21,0x88,
                                        0xab,0xee,0x09,0x35};
    #endif
    #ifdef TEST7
        #define LENGTH 16
            void (*aes_ctr_encrypt)(uint8_t*, uint8_t*, uint8_t*, uint8_t*, uint64_t, uint8_t*) = aes256_ctr_encrypt_export;
            void (*aes_ctr_decrypt)(uint8_t*, uint8_t*, uint8_t*, uint8_t*, uint64_t, uint8_t*) = aes256_ctr_decrypt_export;
            uint8_t K[32] = {0x77,0x6b,0xef,0xf2,0x85,0x1d,0xb0,0x6f,
                            0x4c,0x8a,0x05,0x42,0xc8,0x69,0x6f,0x6c,
                            0x6a,0x81,0xaf,0x1e,0xec,0x96,0xb4,0xd3,
                            0x7f,0xc1,0xd6,0x89,0xe6,0xc1,0xc1,0x04};
            uint8_t IV[8] = {0xdb,0x56,0x72,0xc9,0x7a,0xa8,0xf0,0xb2};
            uint8_t NONCE[4] = {0x00,0x00,0x00,0x60};
            uint8_t P[LENGTH] = {0x53,0x69,0x6e,0x67,0x6c,0x65,0x20,0x62,
                                0x6c,0x6f,0x63,0x6b,0x20,0x6d,0x73,0x67};
            uint8_t E_CIPHER[LENGTH] = {0x14,0x5a,0xd0,0x1d,0xbf,0x82,0x4e,0xc7,
                                        0x56,0x08,0x63,0xdc,0x71,0xe3,0xe0,0xc0};
    #endif
    #ifdef TEST8
        #define LENGTH 32
            void (*aes_ctr_encrypt)(uint8_t*, uint8_t*, uint8_t*, uint8_t*, uint64_t, uint8_t*) = aes256_ctr_encrypt_export;
            void (*aes_ctr_decrypt)(uint8_t*, uint8_t*, uint8_t*, uint8_t*, uint64_t, uint8_t*) = aes256_ctr_decrypt_export;
            uint8_t K[32] = {0xf6,0xd6,0x6d,0x6b,0xd5,0x2d,0x59,0xbb,
                            0x07,0x96,0x36,0x58,0x79,0xef,0xf8,0x86,
                            0xc6,0x6d,0xd5,0x1a,0x5b,0x6a,0x99,0x74,
                            0x4b,0x50,0x59,0x0c,0x87,0xa2,0x38,0x84};
            uint8_t IV[8] = {0xc1,0x58,0x5e,0xf1,0x5a,0x43,0xd8,0x75};
            uint8_t NONCE[4] = {0x00,0xfa,0xac,0x24};
            uint8_t P[LENGTH] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                                0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
                                0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
                                0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f};
            uint8_t E_CIPHER[LENGTH] = {0xf0,0x5e,0x23,0x1b,0x38,0x94,0x61,0x2c,
                                        0x49,0xee,0x00,0x0b,0x80,0x4e,0xb2,0xa9,
                                        0xb8,0x30,0x6b,0x50,0x8f,0x83,0x9d,0x6a,
                                        0x55,0x30,0x83,0x1d,0x93,0x44,0xaf,0x1c};
    #endif
    #ifdef TEST9
        #define LENGTH 36
            void (*aes_ctr_encrypt)(uint8_t*, uint8_t*, uint8_t*, uint8_t*, uint64_t, uint8_t*) = aes256_ctr_encrypt_export;
            void (*aes_ctr_decrypt)(uint8_t*, uint8_t*, uint8_t*, uint8_t*, uint64_t, uint8_t*) = aes256_ctr_decrypt_export;
            uint8_t K[32] = {0xff,0x7a,0x61,0x7c,0xe6,0x91,0x48,0xe4,
                            0xf1,0x72,0x6e,0x2f,0x43,0x58,0x1d,0xe2,
                            0xaa,0x62,0xd9,0xf8,0x05,0x53,0x2e,0xdf,
                            0xf1,0xee,0xd6,0x87,0xfb,0x54,0x15,0x3d};
            uint8_t IV[8] = {0x51,0xa5,0x1d,0x70,0xa1,0xc1,0x11,0x48};
            uint8_t NONCE[4] = {0x00,0x1c,0xc5,0xb7};
            uint8_t P[LENGTH] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                                0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
                                0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
                                0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,
                                0x20,0x21,0x22,0x23};
            uint8_t E_CIPHER[LENGTH] = {0xeb,0x6c,0x52,0x82,0x1d,0x0b,0xbb,0xf7,
                                        0xce,0x75,0x94,0x46,0x2a,0xca,0x4f,0xaa,
                                        0xb4,0x07,0xdf,0x86,0x65,0x69,0xfd,0x07,
                                        0xf4,0x8c,0xc0,0xb5,0x83,0xd6,0x07,0x1f,
                                        0x1e,0xc0,0xe6,0xb8};
    #endif

    // ciphertext output
    uint8_t CIPHER[LENGTH];
    // decrypted text output
    uint8_t DECRYPTED_TEXT[LENGTH];
    /*------------------------------------------------------------
                      ⇑ Initialize test vectors ⇑
    ------------------------------------------------------------*/


    /*------------------------------------------------------------
                    ⇓ Initialize other variables ⇓
    ------------------------------------------------------------*/
    int ret_value = 0;
    int cipher_correct = 1, decrypt_correct = 1;
    int print_mode = 1; // -1 -> less print
                        //  0 -> no print
                        //  1 -> full print

    if (argc >= 2 && strcmp(argv[1], "-lprint") == 0)
        print_mode = -1;
    else if (argc >= 2 && strcmp(argv[1], "-noprint") == 0)
        print_mode = 0;

    /*------------------------------------------------------------
                    ⇑ Initialize other variables ⇑
    ------------------------------------------------------------*/


    /*------------------------------------------------------------
                            ⇓ Run tests ⇓
    ------------------------------------------------------------*/
    aes_ctr_encrypt(P, IV, NONCE, CIPHER, LENGTH, K);
    aes_ctr_decrypt(CIPHER, IV, NONCE, DECRYPTED_TEXT, LENGTH, K);
    /*------------------------------------------------------------
                            ⇑ Run tests ⇑
    ------------------------------------------------------------*/


    /*------------------------------------------------------------
                          ⇓ Test results ⇓
    ------------------------------------------------------------*/
    if (!test_arr(CIPHER, E_CIPHER, LENGTH)) {
        cipher_correct = 0;
        ret_value += 1;
    }

    if (!test_arr(P, DECRYPTED_TEXT, LENGTH)) {
        decrypt_correct = 0;
        ret_value += 8;
    }
    /*------------------------------------------------------------
                          ⇑ Test results ⇑
    ------------------------------------------------------------*/


    /*------------------------------------------------------------
                          ⇓ Print vectors ⇓
    ------------------------------------------------------------*/
    if (print_mode == 1) {
        printf("cipher ⇒ ");  print_num_arr(CIPHER, LENGTH);
        printf("ecipher⇒ ");  print_num_arr(E_CIPHER, LENGTH);
        printf("\n");
        printf("plaintext⇒ ");  print_num_arr(P, LENGTH);
        printf("decrypted⇒ ");  print_num_arr(DECRYPTED_TEXT, LENGTH);
    }
    /*------------------------------------------------------------
                          ⇑ Print vectors ⇑
    ------------------------------------------------------------*/


    /*------------------------------------------------------------
                          ⇓ Print results ⇓
    ------------------------------------------------------------*/
    if (print_mode == 1) {
        if (cipher_correct)
            printf("\n ✔ Expected cipher obtained.");
        else
            printf("\n ✘ WRONG CIPHER OBTAINED!");

        if (decrypt_correct)
            printf("\n ✔ Expected decrypted text obtained.");
        else
            printf("\n ✘ WRONG DECRYPTED TEXT OBTAINED!");
    }
    else if (print_mode == -1) {
        if (cipher_correct && decrypt_correct)
            printf(" ✔ All good.");
        else
            printf(" ✘ SOMETHING WENT WRONG!");
    }
    /*------------------------------------------------------------
                          ⇑ Print results ⇑
    ------------------------------------------------------------*/

    return ret_value;
}