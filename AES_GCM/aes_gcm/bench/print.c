#include "print.h"

static int cmp_uint64(const void *a, const void *b)
{
    if(*(uint64_t *)a < *(uint64_t *)b) return -1;
    if(*(uint64_t *)a > *(uint64_t *)b) return 1;
    return 0;
}

static uint64_t median(uint64_t *l, size_t llen)
{
    qsort(l,llen,sizeof(uint64_t),cmp_uint64);

    if(llen%2) return l[llen/2];
    else return (l[llen/2-1]+l[llen/2])/2;
}

static uint64_t average(uint64_t *t, size_t tlen)
{
    size_t i;
    uint64_t acc=0;

    for(i=0;i<tlen;i++)
        acc += t[i];

    return acc/tlen;
}

static int fill_space(uint64_t n, int size)
{
    int r = 0;
    if (n == 0)(r = 1);
    else {
        while (n != 0) {
        n = n / 10;
        r++;
        };
    };
    return size - r;
}

void print_results(uint64_t *values)
{

    // --------------------------- PRINT CICLOS ---------------------------
    unsigned long long meds[OP], avs[OP];
    char lines[9][256];
    int lengths[9];

    for (int i = 0; i < OP; i++) {
        meds[i] = (unsigned long long) median(&values[i*TIMINGS], TIMINGS);
    }

    for (int i = 0; i < OP; i++) {
        avs[i] = (unsigned long long) average(&values[i*TIMINGS], TIMINGS);
    }

    lengths[0] = sprintf(lines[0], "              ┌─────────┬─────────┐");
    lengths[1] = sprintf(lines[1], "      \e[1mMEDIANA\e[m │ ENCRYPT │ DECRYPT │");
    lengths[2] = sprintf(lines[2], "   ┌──────────┼─────────┼─────────┤");
    lengths[3] = sprintf(lines[3], "   │    C REF │%*s%llu │%*s%llu │", fill_space(meds[C_REF_ENC],8), "", meds[C_REF_ENC], fill_space(meds[C_REF_DEC],8), "", meds[C_REF_DEC]);
    lengths[4] = sprintf(lines[4], "   ├──────────┼─────────┼─────────┤");
    lengths[5] = sprintf(lines[5], "   │ C AES-NI │%*s%llu │%*s%llu │", fill_space(meds[C_AESNI_ENC],8), "", meds[C_AESNI_ENC], fill_space(meds[C_AESNI_DEC],8), "", meds[C_AESNI_DEC]);
    lengths[6] = sprintf(lines[6], "   ├──────────┼─────────┼─────────┤");
    lengths[7] = sprintf(lines[7], "   │   JASMIN │%*s%llu │%*s%llu │", fill_space(meds[JASMIN_ENC],8), "", meds[JASMIN_ENC], fill_space(meds[JASMIN_DEC],8), "", meds[JASMIN_DEC]);
    lengths[8] = sprintf(lines[8], "   └──────────┴─────────┴─────────┘");

    sprintf(lines[0]+lengths[0], "             ┌─────────┬─────────┐\n");
    sprintf(lines[1]+lengths[1], "       \e[1mMÉDIA\e[m │ ENCRYPT │ DECRYPT │\n");
    sprintf(lines[2]+lengths[2], "  ┌──────────┼─────────┼─────────┤\n");
    sprintf(lines[3]+lengths[3], "  │    C REF │%*s%llu │%*s%llu │\n", fill_space(avs[C_REF_ENC],8), "", avs[C_REF_ENC], fill_space(avs[C_REF_DEC],8), "", avs[C_REF_DEC]);
    sprintf(lines[4]+lengths[4], "  ├──────────┼─────────┼─────────┤\n");
    sprintf(lines[5]+lengths[5], "  │ C AES-NI │%*s%llu │%*s%llu │\n", fill_space(avs[C_AESNI_ENC],8), "", avs[C_AESNI_ENC], fill_space(avs[C_AESNI_DEC],8), "", avs[C_AESNI_DEC]);
    sprintf(lines[6]+lengths[6], "  ├──────────┼─────────┼─────────┤\n");
    sprintf(lines[7]+lengths[7], "  │   JASMIN │%*s%llu │%*s%llu │\n", fill_space(avs[JASMIN_ENC],8), "", avs[JASMIN_ENC], fill_space(avs[JASMIN_DEC],8), "", avs[JASMIN_DEC]);
    sprintf(lines[8]+lengths[8], "  └──────────┴─────────┴─────────┘\n");

    printf("\n");
    for (int i = 0; i < 9; i++) {
        printf(lines[i]);
    }
    printf("                 Os valores apresentados referem-se a ciclos do CPU.");


    // --------------------------- PRINT CICLOS POR INLEN ---------------------------
    double meds_d[OP], avs_d[OP];

    for (int i = 0; i < OP; i++) {
        meds_d[i] = (double)(meds[i]) / (double) IN_LEN;
    }

    for (int i = 0; i < OP; i++) {
        avs_d[i] = (double)(avs[i]) / (double) IN_LEN;
    }

    printf("\n\n\n\n");
    lengths[0] = sprintf(lines[0], "              ┌─────────┬─────────┐");
    lengths[1] = sprintf(lines[1], "      \e[1mMEDIANA\e[m │ ENCRYPT │ DECRYPT │");
    lengths[2] = sprintf(lines[2], "   ┌──────────┼─────────┼─────────┤");
    lengths[3] = sprintf(lines[3], "   │    C REF │  %s%02.2lf  │  %s%02.2lf  │", meds_d[C_REF_ENC] < 10 ? " " : "", meds_d[C_REF_ENC], meds_d[C_REF_DEC] < 10 ? " " : "", meds_d[C_REF_DEC]);
    lengths[4] = sprintf(lines[4], "   ├──────────┼─────────┼─────────┤");
    lengths[5] = sprintf(lines[5], "   │ C AES-NI │  %s%02.2lf  │  %s%02.2lf  │", meds_d[C_AESNI_ENC] < 10 ? " " : "", meds_d[C_AESNI_ENC], meds_d[C_AESNI_DEC] < 10 ? " " : "", meds_d[C_AESNI_DEC]);
    lengths[6] = sprintf(lines[6], "   ├──────────┼─────────┼─────────┤");
    lengths[7] = sprintf(lines[7], "   │   JASMIN │  %s%02.2lf  │  %s%02.2lf  │", meds_d[JASMIN_ENC] < 10 ? " " : "", meds_d[JASMIN_ENC], meds_d[JASMIN_DEC] < 10 ? " " : "", meds_d[JASMIN_DEC]);
    lengths[8] = sprintf(lines[8], "   └──────────┴─────────┴─────────┘");

    sprintf(lines[0]+lengths[0], "             ┌─────────┬─────────┐\n");
    sprintf(lines[1]+lengths[1], "       \e[1mMÉDIA\e[m │ ENCRYPT │ DECRYPT │\n");
    sprintf(lines[2]+lengths[2], "  ┌──────────┼─────────┼─────────┤\n");
    sprintf(lines[3]+lengths[3], "  │    C REF │  %s%02.2lf  │  %s%02.2lf  │\n", avs_d[C_REF_ENC] < 10 ? " " : "", avs_d[C_REF_ENC], avs_d[C_REF_DEC] < 10 ? " " : "", avs_d[C_REF_DEC]);
    sprintf(lines[4]+lengths[4], "  ├──────────┼─────────┼─────────┤\n");
    sprintf(lines[5]+lengths[5], "  │ C AES-NI │  %s%02.2lf  │  %s%02.2lf  │\n", avs_d[C_AESNI_ENC] < 10 ? " " : "", avs_d[C_AESNI_ENC], avs_d[C_AESNI_DEC] < 10 ? " " : "", avs_d[C_AESNI_DEC]);
    sprintf(lines[6]+lengths[6], "  ├──────────┼─────────┼─────────┤\n");
    sprintf(lines[7]+lengths[7], "  │   JASMIN │  %s%02.2lf  │  %s%02.2lf  │\n", avs_d[JASMIN_ENC] < 10 ? " " : "", avs_d[JASMIN_ENC], avs_d[JASMIN_DEC] < 10 ? " " : "", avs_d[JASMIN_DEC]);
    sprintf(lines[8]+lengths[8], "  └──────────┴─────────┴─────────┘\n");

    for (int i = 0; i < 9; i++) {
        printf(lines[i]);
    }
    printf("    Os valores apresentados referem-se a ciclos por tamanho do input.\n");

}
