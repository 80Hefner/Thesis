#include <smmintrin.h>
#include <immintrin.h>
#include <wmmintrin.h>
#include <emmintrin.h>
#include <sys/types.h>
#include <stdalign.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

extern int aes128_gcm_decrypt_export(uint8_t** in_ptr,
                                   uint8_t* ivec_ptr,
                                   uint8_t* addt_ptr,
                                   uint8_t* out_ptr,
                                   uint64_t* sizes,
                                   uint8_t* key_ptr);
extern int aes192_gcm_decrypt_export(uint8_t** in_ptr,
                                   uint8_t* ivec_ptr,
                                   uint8_t* addt_ptr,
                                   uint8_t* out_ptr,
                                   uint64_t* sizes,
                                   uint8_t* key_ptr);
extern int aes256_gcm_decrypt_export(uint8_t** in_ptr,
                                   uint8_t* ivec_ptr,
                                   uint8_t* addt_ptr,
                                   uint8_t* out_ptr,
                                   uint64_t* sizes,
                                   uint8_t* key_ptr);


void print_num_arr(uint8_t* arr, int size)
{
    printf("0x");
    for (int i = 0; i < size; i++) {
        printf("%02x", arr[i]);
        if(i%2 == 1) printf(" ");
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

void line_to_array(char* line, size_t size, uint8_t* arr)
{
    char hex[3];
    hex[2] = '\0';
    int num;

    for (int i = 0; i < size; i+=2) {
        hex[0] = line[i];
        hex[1] = line[i+1];
        num = (int) strtol(hex, NULL, 16);
        arr[i/2] = num;
    }
}

int main( int argc, char** argv )
{
    /*------------------------------------------------------------
                        ⇓ Initialize variables ⇓
    ------------------------------------------------------------*/
    int (*aes_gcm_decrypt)(uint8_t**, uint8_t*, uint8_t*, uint8_t*, uint64_t*, uint8_t*) = aes256_gcm_decrypt_export;

    uint64_t NBYTES, ABYTES, IBYTES, TBYTES;
    uint8_t K[32], IV[1024], A[1024], CT[1024], E_PT[1024], E_TAG[16];
    uint8_t DECRYPTED_TEXT[1024];

    uint8_t* DEC_INPUT[2] = {CT, E_TAG};

    int ret_value = 0, debug = 0, e_result = 1;
    int auth_success;
    /*------------------------------------------------------------
                        ⇑ Initialize variables ⇑
    ------------------------------------------------------------*/


    /*------------------------------------------------------------
                        ⇓ Parse arguments ⇓
    ------------------------------------------------------------*/
    for (int i = 1; i < argc; i++) {

        if (strcmp(argv[i], "-key") == 0) {
            i += 1;
            line_to_array(argv[i], strlen(argv[i]), K);

            if (strlen(argv[i]) == 32)
                aes_gcm_decrypt = aes128_gcm_decrypt_export;
            else if (strlen(argv[i]) == 48)
                aes_gcm_decrypt = aes192_gcm_decrypt_export;
            else if (strlen(argv[i]) == 64)
                aes_gcm_decrypt = aes256_gcm_decrypt_export;
        }
        else if (strcmp(argv[i], "-iv") == 0) {
            i += 1;
            line_to_array(argv[i], strlen(argv[i]), IV);
            IBYTES = strlen(argv[i]) / 2;
        }
        else if (strcmp(argv[i], "-ct") == 0) {
            i += 1;
            line_to_array(argv[i], strlen(argv[i]), CT);
            NBYTES = strlen(argv[i]) / 2;
        }
        else if (strcmp(argv[i], "-aad") == 0) {
            i += 1;
            line_to_array(argv[i], strlen(argv[i]), A);
            ABYTES = strlen(argv[i]) / 2;
        }
        else if (strcmp(argv[i], "-pt") == 0) {
            i += 1;
            line_to_array(argv[i], strlen(argv[i]), E_PT);
        }
        else if (strcmp(argv[i], "-tag") == 0) {
            i += 1;
            line_to_array(argv[i], strlen(argv[i]), E_TAG);
            TBYTES = strlen(argv[i]) / 2;
        }
        else if (strcmp(argv[i], "-fail") == 0) {
            e_result = 0;
        }
        else if (strcmp(argv[i], "-debug") == 0)
            debug = 1;
    }
    uint64_t SIZES[4] = {NBYTES, ABYTES, IBYTES, TBYTES};
    /*------------------------------------------------------------
                        ⇑ Parse variables ⇑
    ------------------------------------------------------------*/


    /*------------------------------------------------------------
                            ⇓ Run tests ⇓
    ------------------------------------------------------------*/
    auth_success = aes_gcm_decrypt(DEC_INPUT, IV, A, DECRYPTED_TEXT, SIZES, K);
    /*------------------------------------------------------------
                            ⇑ Run tests ⇑
    ------------------------------------------------------------*/


    /*------------------------------------------------------------
                          ⇓ Test results ⇓
    ------------------------------------------------------------*/
    if (auth_success != e_result)
        ret_value += 1;

    if (!test_arr(DECRYPTED_TEXT, E_PT, NBYTES) && e_result)
        ret_value += 2;

    /*------------------------------------------------------------
                          ⇑ Test results ⇑
    ------------------------------------------------------------*/


    /*------------------------------------------------------------
                          ⇓ Print vectors ⇓
    ------------------------------------------------------------*/
    if (debug == 1) {
        printf("------------------------------------------------------------\n");
        printf("                        ⇓ DEBUG ⇓\n");
        printf("------------------------------------------------------------\n");
        printf("plain ⇒ ");  print_num_arr(DECRYPTED_TEXT, NBYTES);
        printf("eplain⇒ ");  print_num_arr(E_PT, NBYTES);
        printf("------------------------------------------------------------\n");
        printf("                        ⇑ DEBUG ⇑\n");
        printf("------------------------------------------------------------\n");
    }
    /*------------------------------------------------------------
                          ⇑ Print vectors ⇑
    ------------------------------------------------------------*/


    return ret_value;
}
