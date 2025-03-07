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

extern uint64_t p384_keypair_export(uint8_t* secret_key, uint8_t** public_key);
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
    uint8_t secret_key[SK_LEN] = {};
    uint8_t public_key[2][SK_LEN] = {};
    uint8_t message[MSG_LEN] = "Example of ECDSA with P-384";
    uint8_t signed_message[MSG_LEN + SIGN_LEN] = {};
    uint64_t signed_message_length = 0;
    uint8_t vmessage[MSG_LEN] = {};
    uint64_t vmessage_length;
    uint64_t status = 0;

    p384_keypair_export(secret_key, (uint8_t**) public_key);

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
