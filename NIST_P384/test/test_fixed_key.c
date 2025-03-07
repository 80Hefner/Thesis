#include <smmintrin.h>
#include <immintrin.h>
#include <wmmintrin.h>
#include <emmintrin.h>
#include <sys/types.h>
#include <stdalign.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define SK_LEN 48
#define SIGN_LEN 96
#define MSG_LEN 27

extern uint64_t p384_gen_public_key(uint8_t* secret_key, uint8_t** public_key);
extern uint64_t p384_sign_export(uint8_t* signed_message,
                                 uint64_t* signed_message_length,
                                 uint8_t* message,
                                 uint64_t message_length,
                                 uint8_t* secret_key);
extern uint64_t p384_open_export(uint8_t* message,
                                 uint64_t* message_length,
                                 uint8_t* signed_message,
                                 uint64_t signed_message_length,
                                 uint8_t* public_key);


void print_num_arr_rev(uint8_t* arr, int size)
{
    printf("0x");
    for (int i = size-1, j = 0; i >= 0; i--, j++) {
        if (j == 8) {
            printf(" ");
            j = 0;
        }
        printf("%02x", arr[i]);
    }
    printf("\n");
}

void print_num_arr(uint8_t* arr, int size)
{
    printf("0x");
    for (int i = 0, j = 0; i < size; i++, j++) {
        if (j == 8) {
            printf(" ");
            j = 0;
        }
        printf("%02x", arr[i]);
    }
    printf("\n");
}

int main( int argc, char** argv )
{
    uint8_t secret_key[SK_LEN] = {0x08,0x8a,0x3f,0xd8,0x57,0x4b,0x22,0xd1,
                                  0x14,0x97,0x6b,0x5e,0x56,0xa8,0x93,0xe3,
                                  0x0a,0x6a,0x2e,0x39,0xfc,0x3d,0xe7,0x55,
                                  0x04,0xcb,0x6a,0xfc,0x4a,0xae,0xfa,0xb4,
                                  0xe3,0xa3,0xe3,0x6c,0x1c,0x4b,0x58,0xc0,
                                  0x48,0x4b,0x9e,0x62,0xed,0x02,0x2c,0xf9};
    uint8_t public_key[2][SK_LEN] = {{0xb5,0x5c,0x0f,0xef,0xd9,0x89,0x64,0x08,
                                      0xf9,0x82,0x7b,0x65,0x74,0xab,0xd2,0xb9,
                                      0x1f,0x47,0xe6,0x61,0x3c,0x24,0x71,0x50,
                                      0x36,0x87,0xb4,0xf2,0x90,0x43,0x56,0xf2,
                                      0x26,0x91,0xf0,0x43,0x53,0x45,0xf1,0xd5,
                                      0xb4,0x36,0x9d,0x9e,0xbc,0x01,0xf7,0x3b},
                                     {0x55,0xb8,0x8d,0xb6,0xb5,0xa9,0x44,0x03,
                                      0xa3,0xcd,0xcf,0x00,0x2d,0x38,0xe5,0xff,
                                      0x95,0x62,0x2a,0x55,0x83,0x55,0x32,0x99,
                                      0x31,0x44,0x01,0x51,0x7a,0x13,0x5b,0xf7,
                                      0x6f,0xaa,0xbd,0xcc,0x55,0x38,0x53,0x8d,
                                      0xe6,0x52,0xf9,0xfb,0xea,0x58,0xa3,0xd1}
                                    };
    uint8_t message[MSG_LEN] = "Example of ECDSA with P-384";
    uint8_t signed_message[MSG_LEN + SIGN_LEN] = {};
    uint64_t signed_message_length = 0;
    uint8_t vmessage[MSG_LEN] = {};
    uint64_t vmessage_length;
    uint64_t status = 0;

    // --- KEYS ---
    printf("----------------------------------------------------------KEYS----------------------------------------------------------\n");
    printf("SK: ");
    print_num_arr_rev(secret_key, 48);

    printf("PK_x: ");
    print_num_arr_rev(public_key[0], 48);

    printf("PK_y: ");
    print_num_arr_rev(public_key[1], 48);


    // --- SIGN ---
    p384_sign_export(signed_message, &signed_message_length, message, MSG_LEN, secret_key);
    printf("----------------------------------------------------------SIGN----------------------------------------------------------\n");
    
    printf("Msg: ");
    print_num_arr(signed_message+SIGN_LEN, MSG_LEN);

    printf("  R: ");
    print_num_arr(signed_message, SIGN_LEN/2);

    printf("  S: ");
    print_num_arr(signed_message+SIGN_LEN/2, SIGN_LEN/2);

    printf("\n");
    printf(" SM: "); print_num_arr(signed_message, signed_message_length);
    printf("LEN: %lu bytes\n", signed_message_length);


    // --- VERIFY ---
    status = p384_open_export(vmessage, &vmessage_length, signed_message, signed_message_length, (uint8_t*)public_key);
    printf("------------------------------------------------------VERIFICATION------------------------------------------------------\n");

    printf(status==1 ? "VERIFICATION SUCCESSFUL!\n" : "ERROR IN VERIFICATION!\n");

    printf("Msg: "); print_num_arr(vmessage, MSG_LEN);
    printf("LEN: %lu bytes\n", vmessage_length);

    return 0;
}
