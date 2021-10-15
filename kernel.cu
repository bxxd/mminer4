/*
    To use this source, cite the paper with the following bibtex:

    @inproceedings{DBLP:conf/crypto/SongLG17,
    author    = {Ling Song and Guohong Liao and Jian Guo},
    title     = {{Non-full Sbox Linearization: Applications to Collision Attacks on Round-Reduced Keccak}},
    booktitle = {Advances in Cryptology - {CRYPTO} 2017 - 37th Annual International Cryptology Conference, Santa Barbara, CA, USA, August 20-24, 2017, Proceedings, Part {II}},
    pages     = {428--451},
    year      = {2017},
    crossref  = {DBLP:conf/crypto/2017-2},
    url       = {https://doi.org/10.1007/978-3-319-63715-0_15},
    doi       = {10.1007/978-3-319-63715-0_15},
    timestamp = {Tue, 15 Aug 2017 07:01:19 +0200},
    biburl    = {http://dblp.org/rec/bib/conf/crypto/SongLG17},
    bibsource = {dblp computer science bibliography, http://dblp.org}
    }
    @proceedings{DBLP:conf/crypto/2017-2,
    editor    = {Jonathan Katz and Hovav Shacham},
    title     = {Advances in Cryptology - {CRYPTO} 2017 - 37th Annual International Cryptology Conference, Santa Barbara, CA, USA, August 20-24, 2017, Proceedings, Part {II}},
    series    = {Lecture Notes in Computer Science},
    volume    = {10402},
    publisher = {Springer},
    year      = {2017},
    url       = {https://doi.org/10.1007/978-3-319-63715-0},
    doi       = {10.1007/978-3-319-63715-0},
    isbn      = {978-3-319-63714-3},
    timestamp = {Mon, 14 Aug 2017 14:37:57 +0200},
    biburl    = {http://dblp.org/rec/bib/conf/crypto/2017-2},
    bibsource = {dblp computer science bibliography, http://dblp.org}
    }

    rewritten for mpunks @bxxd
*/

#include "kernel.h"

using namespace std;

void logger(const char *priority, const char *format, va_list ap)
{

    // Sanity-check parameters
    if (!format)
        return;

    va_list ac;
    va_copy(ac, ap);

    struct tm t;
    time_t ltime = time(NULL);
    gmtime_r(&ltime, &t);
    printf("[%04d-%02d-%02d %02d:%02d:%02d] [%s] ",
           (t.tm_year + 1900), (t.tm_mon + 1), t.tm_mday,
           t.tm_hour, t.tm_min, t.tm_sec,
           priority);
    vprintf(format, ac);

    va_end(ac);
}

void log_sensitive(const char *format, ...)
{
    // print_datetime();
#if FULL
    va_list ap;
    va_start(ap, format);
    logger("INFO", format, ap);
    va_end(ap);
#endif
}

void log_info(const char *format, ...)
{
    // print_datetime();

    va_list ap;
    va_start(ap, format);
    logger("INFO", format, ap);
    va_end(ap);
}

void log_err(const char *format, ...)
{
    // print_datetime();

    va_list ap;
    va_start(ap, format);
    logger("ERROR", format, ap);
    va_end(ap);
}

__device__ uint64_t device_difficulty_upper = 0;
__device__ uint64_t device_difficulty_lower = 5731203885580;

__device__ uint64_t device_minor_upper = 0;
__device__ uint64_t device_minor_lower = 0;

texture<unsigned int, 1, cudaReadModeElementType>
    texreference_input;

__constant__ uint64_t RC[24] = {
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
    0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008};

#define ROL(x, n) (((x) << (n)) | ((x) >> ((uint64_t)64 - (n))))

uint64_t rand_uint64(void)
{
    uint64_t r = 0;
    for (int i = 0; i < 64; i += 15 /*30*/)
    {
        r = r * ((uint64_t)RAND_MAX + 1) + rand();
    }
    return r;
}

//assume each inputs have the same input length

__device__ uint32_t device_hash_count = 0;
__device__ uint64_t device_found_nonce = 0;
__device__ uint64_t device_found_minor = 0;

__global__ void Keccak1600(const int inputByte, uint8_t *output, const int outputByte, uint64_t startNonce)
{

    uint32_t num_keccak_blocks = inputByte / (DATA_BLOCK_SIZE << 1);

    uint64_t state00 = 0, state01 = 0, state02 = 0, state03 = 0, state04 = 0,
             state10 = 0, state11 = 0, state12 = 0, state13 = 0, state14 = 0,
             state20 = 0, state21 = 0, state22 = 0, state23 = 0, state24 = 0,
             state30 = 0, state31 = 0, state32 = 0, state33 = 0, state34 = 0,
             state40 = 0, state41 = 0, state42 = 0, state43 = 0, state44 = 0;
    uint64_t tmpState00 = 0, tmpState01 = 0, tmpState02 = 0, tmpState03 = 0, tmpState04 = 0,
             tmpState10 = 0, tmpState11 = 0, tmpState12 = 0, tmpState13 = 0, tmpState14 = 0,
             tmpState20 = 0, tmpState21 = 0, tmpState22 = 0, tmpState23 = 0, tmpState24 = 0,
             tmpState30 = 0, tmpState31 = 0, tmpState32 = 0, tmpState33 = 0, tmpState34 = 0,
             tmpState40 = 0, tmpState41 = 0, tmpState42 = 0, tmpState43 = 0, tmpState44 = 0;
    uint64_t Csum0, Csum1, Csum2, Csum3, Csum4, D0, D1, D2, D3, D4;

    uint64_t thread = blockDim.x * blockIdx.x + threadIdx.x;
    uint64_t nonce = startNonce + thread;

    // nonce = startNonce + device_hash_count;

#if DEBUG
    // printf("nonce=%lu/0x%016x\n", nonce, nonce);
    printf("n=%lu t=%lu nk=%d bdim=%d bid=%d tid=%d\n", nonce, thread, num_keccak_blocks,
           blockDim.x, blockIdx.x, threadIdx.x);

    printf("minor difficulty=%lx%016lx\n", device_minor_upper, device_minor_lower);
#else
    // printf("n=%lu t=%lu nk=%d bdim=%d bid=%d tid=%d\n", nonce, thread, num_keccak_blocks,
    //        blockDim.x, blockIdx.x, threadIdx.x);

    // if (nonce == 609667058559510631)
    // {
    //     printf("here!!!!\n");
    //     printf("n=%lu t=%lu nk=%d bdim=%d bid=%d tid=%d\n", nonce, thread, num_keccak_blocks,
    //            blockDim.x, blockIdx.x, threadIdx.x);
    // }
#endif

    uint64_t save_state00, save_state01, save_state02, save_state03;

    //absoring phase
    for (int k = 0; k < num_keccak_blocks; k++)
    {

#if 0 < DATA_BLOCK_SIZE
        // state00 ^= input[(blockIdx.x*BLOCKX + threadIdx.x)*inputByte+ DATA_BLOCK_SIZE*k];
        state00 ^= (uint64_t)tex1Dfetch(texreference_input, (blockIdx.x*BLOCKX + threadIdx.x)*inputByte+ DATA_BLOCK_SIZE*k) ^ ((uint64_t)tex1Dfetch(texreference_input, (blockIdx.x*BLOCKX + threadIdx.x)*inputByte+ DATA_BLOCK_SIZE*k+1) << 32);
        // printf("%016llX\n", state00);
#endif

#if 1 < DATA_BLOCK_SIZE
        // state01 ^= input[(blockIdx.x*BLOCKX + threadIdx.x)*inputByte+ DATA_BLOCK_SIZE*k+1];
        state01 ^= (uint64_t)tex1Dfetch(texreference_input, (blockIdx.x * BLOCKX + threadIdx.x) * inputByte + DATA_BLOCK_SIZE * k + 2) ^ ((uint64_t)tex1Dfetch(texreference_input, (blockIdx.x * BLOCKX + threadIdx.x) * inputByte + DATA_BLOCK_SIZE * k + 3) << 32);

#endif

#if 2 < DATA_BLOCK_SIZE
        // state02 ^= input[(blockIdx.x*BLOCKX + threadIdx.x)*inputByte+ DATA_BLOCK_SIZE*k+2];
        state02 ^= (uint64_t)tex1Dfetch(texreference_input, (blockIdx.x * BLOCKX + threadIdx.x) * inputByte + DATA_BLOCK_SIZE * k + 4) ^ ((uint64_t)tex1Dfetch(texreference_input, (blockIdx.x * BLOCKX + threadIdx.x) * inputByte + DATA_BLOCK_SIZE * k + 5) << 32);

#endif

#if 3 < DATA_BLOCK_SIZE
        // state03 ^= input[(blockIdx.x*BLOCKX + threadIdx.x)*inputByte+ DATA_BLOCK_SIZE*k+3];
        state03 ^= (uint64_t)tex1Dfetch(texreference_input, (blockIdx.x * BLOCKX + threadIdx.x) * inputByte + DATA_BLOCK_SIZE * k + 6) ^ ((uint64_t)tex1Dfetch(texreference_input, (blockIdx.x * BLOCKX + threadIdx.x) * inputByte + DATA_BLOCK_SIZE * k + 7) << 32);

#endif

#if 4 < DATA_BLOCK_SIZE
        // state04 ^= input[(blockIdx.x*BLOCKX + threadIdx.x)*inputByte+ DATA_BLOCK_SIZE*k+4];
        state04 ^= (uint64_t)tex1Dfetch(texreference_input, (blockIdx.x * BLOCKX + threadIdx.x) * inputByte + DATA_BLOCK_SIZE * k + 8) ^ ((uint64_t)tex1Dfetch(texreference_input, (blockIdx.x * BLOCKX + threadIdx.x) * inputByte + DATA_BLOCK_SIZE * k + 9) << 32);

#endif

#if 5 < DATA_BLOCK_SIZE
        // state10 ^= input[(blockIdx.x*BLOCKX + threadIdx.x)*inputByte+ DATA_BLOCK_SIZE*k+5];
        state10 ^= (uint64_t)tex1Dfetch(texreference_input, (blockIdx.x * BLOCKX + threadIdx.x) * inputByte + DATA_BLOCK_SIZE * k + 10) ^ ((uint64_t)tex1Dfetch(texreference_input, (blockIdx.x * BLOCKX + threadIdx.x) * inputByte + DATA_BLOCK_SIZE * k + 11) << 32);

#endif

#if 6 < DATA_BLOCK_SIZE
        // state11 ^= input[(blockIdx.x*BLOCKX + threadIdx.x)*inputByte+ DATA_BLOCK_SIZE*k+6];
        state11 ^= (uint64_t)tex1Dfetch(texreference_input, (blockIdx.x * BLOCKX + threadIdx.x) * inputByte + DATA_BLOCK_SIZE * k + 12) ^ ((uint64_t)tex1Dfetch(texreference_input, (blockIdx.x * BLOCKX + threadIdx.x) * inputByte + DATA_BLOCK_SIZE * k + 13) << 32);

#endif

#if 7 < DATA_BLOCK_SIZE
        // state12 ^= input[(blockIdx.x*BLOCKX + threadIdx.x)*inputByte+ DATA_BLOCK_SIZE*k+7];
        state12 ^= (uint64_t)tex1Dfetch(texreference_input, (blockIdx.x * BLOCKX + threadIdx.x) * inputByte + DATA_BLOCK_SIZE * k + 14) ^ ((uint64_t)tex1Dfetch(texreference_input, (blockIdx.x * BLOCKX + threadIdx.x) * inputByte + DATA_BLOCK_SIZE * k + 15) << 32);

#endif

#if 8 < DATA_BLOCK_SIZE
        // state13 ^= input[(blockIdx.x*BLOCKX + threadIdx.x)*inputByte+ DATA_BLOCK_SIZE*k+8];
        state13 ^= (uint64_t)tex1Dfetch(texreference_input, (blockIdx.x * BLOCKX + threadIdx.x) * inputByte + DATA_BLOCK_SIZE * k + 16) ^ ((uint64_t)tex1Dfetch(texreference_input, (blockIdx.x * BLOCKX + threadIdx.x) * inputByte + DATA_BLOCK_SIZE * k + 17) << 32);

#endif

#if 9 < DATA_BLOCK_SIZE
        // state14 ^= input[(blockIdx.x*BLOCKX + threadIdx.x)*inputByte+ DATA_BLOCK_SIZE*k+9];
        state14 ^= (uint64_t)tex1Dfetch(texreference_input, (blockIdx.x * BLOCKX + threadIdx.x) * inputByte + DATA_BLOCK_SIZE * k + 18) ^ ((uint64_t)tex1Dfetch(texreference_input, (blockIdx.x * BLOCKX + threadIdx.x) * inputByte + DATA_BLOCK_SIZE * k + 19) << 32);

#endif

#if 10 < DATA_BLOCK_SIZE
        // state20 ^= input[(blockIdx.x*BLOCKX + threadIdx.x)*inputByte+ DATA_BLOCK_SIZE*k+10];
        state20 ^= (uint64_t)tex1Dfetch(texreference_input, (blockIdx.x * BLOCKX + threadIdx.x) * inputByte + DATA_BLOCK_SIZE * k + 20) ^ ((uint64_t)tex1Dfetch(texreference_input, (blockIdx.x * BLOCKX + threadIdx.x) * inputByte + DATA_BLOCK_SIZE * k + 21) << 32);

#endif

#if 11 < DATA_BLOCK_SIZE
        // state21 ^= input[(blockIdx.x*BLOCKX + threadIdx.x)*inputByte+ DATA_BLOCK_SIZE*k+11];
        state21 ^= (uint64_t)tex1Dfetch(texreference_input, (blockIdx.x * BLOCKX + threadIdx.x) * inputByte + DATA_BLOCK_SIZE * k + 22) ^ ((uint64_t)tex1Dfetch(texreference_input, (blockIdx.x * BLOCKX + threadIdx.x) * inputByte + DATA_BLOCK_SIZE * k + 23) << 32);

#endif

#if 12 < DATA_BLOCK_SIZE
        // state22 ^= input[(blockIdx.x*BLOCKX + threadIdx.x)*inputByte+ DATA_BLOCK_SIZE*k+12];
        state22 ^= (uint64_t)tex1Dfetch(texreference_input, (blockIdx.x * BLOCKX + threadIdx.x) * inputByte + DATA_BLOCK_SIZE * k + 24) ^ ((uint64_t)tex1Dfetch(texreference_input, (blockIdx.x * BLOCKX + threadIdx.x) * inputByte + DATA_BLOCK_SIZE * k + 25) << 32);

#endif

#if 13 < DATA_BLOCK_SIZE
        // state23 ^= input[(blockIdx.x*BLOCKX + threadIdx.x)*inputByte+ DATA_BLOCK_SIZE*k+13];
        state23 ^= (uint64_t)tex1Dfetch(texreference_input, (blockIdx.x * BLOCKX + threadIdx.x) * inputByte + DATA_BLOCK_SIZE * k + 26) ^ ((uint64_t)tex1Dfetch(texreference_input, (blockIdx.x * BLOCKX + threadIdx.x) * inputByte + DATA_BLOCK_SIZE * k + 27) << 32);

#endif

#if 14 < DATA_BLOCK_SIZE
        // state24 ^= input[(blockIdx.x*BLOCKX + threadIdx.x)*inputByte+ DATA_BLOCK_SIZE*k+14];
        state24 ^= (uint64_t)tex1Dfetch(texreference_input, (blockIdx.x * BLOCKX + threadIdx.x) * inputByte + DATA_BLOCK_SIZE * k + 28) ^ ((uint64_t)tex1Dfetch(texreference_input, (blockIdx.x * BLOCKX + threadIdx.x) * inputByte + DATA_BLOCK_SIZE * k + 29) << 32);

#endif

#if 15 < DATA_BLOCK_SIZE
        // state30 ^= input[(blockIdx.x*BLOCKX + threadIdx.x)*inputByte+ DATA_BLOCK_SIZE*k+15];
        state30 ^= (uint64_t)tex1Dfetch(texreference_input, (blockIdx.x * BLOCKX + threadIdx.x) * inputByte + DATA_BLOCK_SIZE * k + 30) ^ ((uint64_t)tex1Dfetch(texreference_input, (blockIdx.x * BLOCKX + threadIdx.x) * inputByte + DATA_BLOCK_SIZE * k + 31) << 32);

#endif

#if 16 < DATA_BLOCK_SIZE
        // state31 ^= input[(blockIdx.x*BLOCKX + threadIdx.x)*inputByte+ DATA_BLOCK_SIZE*k+16];
        state31 ^= (uint64_t)tex1Dfetch(texreference_input, (blockIdx.x * BLOCKX + threadIdx.x) * inputByte + DATA_BLOCK_SIZE * k + 32) ^ ((uint64_t)tex1Dfetch(texreference_input, (blockIdx.x * BLOCKX + threadIdx.x) * inputByte + DATA_BLOCK_SIZE * k + 33) << 32);

#endif

#if 17 < DATA_BLOCK_SIZE
        // state32 ^= input[(blockIdx.x*BLOCKX + threadIdx.x)*inputByte+ DATA_BLOCK_SIZE*k+17];
        state32 ^= (uint64_t)tex1Dfetch(texreference_input, (blockIdx.x * BLOCKX + threadIdx.x) * inputByte + DATA_BLOCK_SIZE * k + 34) ^ ((uint64_t)tex1Dfetch(texreference_input, (blockIdx.x * BLOCKX + threadIdx.x) * inputByte + DATA_BLOCK_SIZE * k + 35) << 32);

#endif

#if 18 < DATA_BLOCK_SIZE
        // state33 ^= input[(blockIdx.x*BLOCKX + threadIdx.x)*inputByte+ DATA_BLOCK_SIZE*k+18];
        state33 ^= (uint64_t)tex1Dfetch(texreference_input, (blockIdx.x * BLOCKX + threadIdx.x) * inputByte + DATA_BLOCK_SIZE * k + 36) ^ ((uint64_t)tex1Dfetch(texreference_input, (blockIdx.x * BLOCKX + threadIdx.x) * inputByte + DATA_BLOCK_SIZE * k + 37) << 32);

#endif

#if 19 < DATA_BLOCK_SIZE
        // state34 ^= input[(blockIdx.x*BLOCKX + threadIdx.x)*inputByte+ DATA_BLOCK_SIZE*k+19];
        state34 ^= (uint64_t)tex1Dfetch(texreference_input, (blockIdx.x * BLOCKX + threadIdx.x) * inputByte + DATA_BLOCK_SIZE * k + 38) ^ ((uint64_t)tex1Dfetch(texreference_input, (blockIdx.x * BLOCKX + threadIdx.x) * inputByte + DATA_BLOCK_SIZE * k + 39) << 32);

#endif

#if 20 < DATA_BLOCK_SIZE
        // state40 ^= input[(blockIdx.x*BLOCKX + threadIdx.x)*inputByte+ DATA_BLOCK_SIZE*k+20];
        state40 ^= (uint64_t)tex1Dfetch(texreference_input, (blockIdx.x * BLOCKX + threadIdx.x) * inputByte + DATA_BLOCK_SIZE * k + 40) ^ ((uint64_t)tex1Dfetch(texreference_input, (blockIdx.x * BLOCKX + threadIdx.x) * inputByte + DATA_BLOCK_SIZE * k + 41) << 32);

#endif

#if 21 < DATA_BLOCK_SIZE
        // state41 ^= input[(blockIdx.x*BLOCKX + threadIdx.x)*inputByte+ DATA_BLOCK_SIZE*k+21];
        state41 ^= (uint64_t)tex1Dfetch(texreference_input, (blockIdx.x * BLOCKX + threadIdx.x) * inputByte + DATA_BLOCK_SIZE * k + 42) ^ ((uint64_t)tex1Dfetch(texreference_input, (blockIdx.x * BLOCKX + threadIdx.x) * inputByte + DATA_BLOCK_SIZE * k + 43) << 32);

#endif

#if 22 < DATA_BLOCK_SIZE
        // state42 ^= input[(blockIdx.x*BLOCKX + threadIdx.x)*inputByte+ DATA_BLOCK_SIZE*k+22];
        state42 ^= (uint64_t)tex1Dfetch(texreference_input, (blockIdx.x * BLOCKX + threadIdx.x) * inputByte + DATA_BLOCK_SIZE * k + 44) ^ ((uint64_t)tex1Dfetch(texreference_input, (blockIdx.x * BLOCKX + threadIdx.x) * inputByte + DATA_BLOCK_SIZE * k + 45) << 32);

#endif

#if 23 < DATA_BLOCK_SIZE
        // state43 ^= input[(blockIdx.x*BLOCKX + threadIdx.x)*inputByte+ DATA_BLOCK_SIZE*k+23];
        state43 ^= (uint64_t)tex1Dfetch(texreference_input, (blockIdx.x * BLOCKX + threadIdx.x) * inputByte + DATA_BLOCK_SIZE * k + 46) ^ ((uint64_t)tex1Dfetch(texreference_input, (blockIdx.x * BLOCKX + threadIdx.x) * inputByte + DATA_BLOCK_SIZE * k + 47) << 32);

#endif

#if 24 < DATA_BLOCK_SIZE
        // state44 ^= input[(blockIdx.x*BLOCKX + threadIdx.x)*inputByte+ DATA_BLOCK_SIZE*k+24];
        state44 ^= (uint64_t)tex1Dfetch(texreference_input, (blockIdx.x * BLOCKX + threadIdx.x) * inputByte + DATA_BLOCK_SIZE * k + 48) ^ ((uint64_t)tex1Dfetch(texreference_input, (blockIdx.x * BLOCKX + threadIdx.x) * inputByte + DATA_BLOCK_SIZE * k + 49) << 32);
#endif

        state03 = cuda_swab64(nonce);

        save_state00 = cuda_swab64(state00);
        save_state01 = cuda_swab64(state01);
        save_state02 = cuda_swab64(state02);
        save_state03 = cuda_swab64(state03);
#if DEBUG
        printf("MSG:\n0x%016lx%016lx%016lx%016lx\n",
               cuda_swab64(state00),
               cuda_swab64(state01),
               cuda_swab64(state02),
               cuda_swab64(state03));
#endif
        // if (nonce == 609667058559510631)
        // {
        //     printf("MSG:\n0x%016lx%016lx%016lx%016lx\n",
        //            cuda_swab64(state00),
        //            cuda_swab64(state01),
        //            cuda_swab64(state02),
        //            cuda_swab64(state03));
        // }

#pragma unroll 4
        for (int i = 0; i < Nr; i++)
        {
            Csum0 = state00 ^ state10 ^ state20 ^ state30 ^ state40;
            Csum1 = state01 ^ state11 ^ state21 ^ state31 ^ state41;
            Csum2 = state02 ^ state12 ^ state22 ^ state32 ^ state42;
            Csum3 = state03 ^ state13 ^ state23 ^ state33 ^ state43;
            Csum4 = state04 ^ state14 ^ state24 ^ state34 ^ state44;
            //
            D0 = Csum4 ^ ROL(Csum1, 1);
            D1 = Csum0 ^ ROL(Csum2, 1);
            D2 = Csum1 ^ ROL(Csum3, 1);
            D3 = Csum2 ^ ROL(Csum4, 1);
            D4 = Csum3 ^ ROL(Csum0, 1);

            state00 ^= D0;
            state01 ^= D1;
            state02 ^= D2;
            state03 ^= D3;
            state04 ^= D4;
            tmpState00 = state00;
            tmpState20 = ROL(state01, 1);
            tmpState40 = ROL(state02, 62);
            tmpState10 = ROL(state03, 28);
            tmpState30 = ROL(state04, 27);

            state10 ^= D0;
            state11 ^= D1;
            state12 ^= D2;
            state13 ^= D3;
            state14 ^= D4;

            tmpState31 = ROL(state10, 36);
            tmpState01 = ROL(state11, 44);
            tmpState21 = ROL(state12, 6);
            tmpState41 = ROL(state13, 55);
            tmpState11 = ROL(state14, 20);

            state20 ^= D0;
            state21 ^= D1;
            state22 ^= D2;
            state23 ^= D3;
            state24 ^= D4;

            tmpState12 = ROL(state20, 3);
            tmpState32 = ROL(state21, 10);
            tmpState02 = ROL(state22, 43);
            tmpState22 = ROL(state23, 25);
            tmpState42 = ROL(state24, 39);

            state30 ^= D0;
            state31 ^= D1;
            state32 ^= D2;
            state33 ^= D3;
            state34 ^= D4;

            tmpState43 = ROL(state30, 41);
            tmpState13 = ROL(state31, 45);
            tmpState33 = ROL(state32, 15);
            tmpState03 = ROL(state33, 21);
            tmpState23 = ROL(state34, 8);

            state40 ^= D0;
            state41 ^= D1;
            state42 ^= D2;
            state43 ^= D3;
            state44 ^= D4;

            //
            tmpState24 = ROL(state40, 18);
            tmpState44 = ROL(state41, 2);
            tmpState14 = ROL(state42, 61);
            tmpState34 = ROL(state43, 56);
            tmpState04 = ROL(state44, 14);

            //
            state00 = tmpState00 ^ ((~tmpState01) & tmpState02);
            state10 = tmpState10 ^ ((~tmpState11) & tmpState12);
            state20 = tmpState20 ^ ((~tmpState21) & tmpState22);
            state30 = tmpState30 ^ ((~tmpState31) & tmpState32);
            state40 = tmpState40 ^ ((~tmpState41) & tmpState42);

            state01 = tmpState01 ^ ((~tmpState02) & tmpState03);
            state11 = tmpState11 ^ ((~tmpState12) & tmpState13);
            state21 = tmpState21 ^ ((~tmpState22) & tmpState23);
            state31 = tmpState31 ^ ((~tmpState32) & tmpState33);
            state41 = tmpState41 ^ ((~tmpState42) & tmpState43);

            state02 = tmpState02 ^ ((~tmpState03) & tmpState04);
            state12 = tmpState12 ^ ((~tmpState13) & tmpState14);
            state22 = tmpState22 ^ ((~tmpState23) & tmpState24);
            state32 = tmpState32 ^ ((~tmpState33) & tmpState34);
            state42 = tmpState42 ^ ((~tmpState43) & tmpState44);

            state03 = tmpState03 ^ ((~tmpState04) & tmpState00);
            state13 = tmpState13 ^ ((~tmpState14) & tmpState10);
            state23 = tmpState23 ^ ((~tmpState24) & tmpState20);
            state33 = tmpState33 ^ ((~tmpState34) & tmpState30);
            state43 = tmpState43 ^ ((~tmpState44) & tmpState40);

            state04 = tmpState04 ^ ((~tmpState00) & tmpState01);
            state14 = tmpState14 ^ ((~tmpState10) & tmpState11);
            state24 = tmpState24 ^ ((~tmpState20) & tmpState21);
            state34 = tmpState34 ^ ((~tmpState30) & tmpState31);
            state44 = tmpState44 ^ ((~tmpState40) & tmpState41);

            state00 ^= RC[i];
        }
    }

    //     //squeezing phase;
    // #if 0 < HASH_SIZE
    //     memcpy(output+(blockIdx.x*BLOCKX + threadIdx.x)*HASH_SIZE, &state00, 8);
    // #endif

    // #if 8 < HASH_SIZE
    //     memcpy(output + (blockIdx.x * BLOCKX + threadIdx.x) * HASH_SIZE + 8, &state01, 8);
    // #endif

    // #if 16 < HASH_SIZE
    //     memcpy(output + (blockIdx.x * BLOCKX + threadIdx.x) * HASH_SIZE + 16, &state02, 8);
    // #endif

    // #if 24 < HASH_SIZE
    //     memcpy(output + (blockIdx.x * BLOCKX + threadIdx.x) * HASH_SIZE + 24, &state03, 8);
    // #endif

#if DEBUG
    // printf("state:0x%016lx\n", cuda_swab64(state00));
    printf("nonce=0x%016lx\nOUT: \n0x%016lx%016lx%016lx%016lx\n",
           nonce,
           cuda_swab64(state00),
           cuda_swab64(state01),
           cuda_swab64(state02),
           cuda_swab64(state03));
#endif

    bool found = 0;
    uint32_t upper = 0;
    uint64_t lower = 0;

    lower = cuda_swab64(state03);
    upper = cuda_swab64(state02);
    upper = upper << 8;

    if (device_difficulty_upper && upper < device_difficulty_upper)
    {
        found = 1;
    }
    else
    {

        if (device_difficulty_upper == upper && lower < device_difficulty_lower)
        {
            found = 1;
        }
    }

    if (found)
    {

        // device_found_nonce = nonce;
        printf("IN: \n0x%016lx%016lx%016lx%016lx\n OUT: \n0x%016lx%016lx%016lx%016lx\n",
               save_state00,
               save_state01,
               save_state02,
               save_state03,
               cuda_swab64(state00),
               cuda_swab64(state01),
               cuda_swab64(state02),
               cuda_swab64(state03));
        printf(">>> FOUND XXX nonce=%lu/0x%016lx combined=0x%06lx%016lx difficulty=0x%06lx%016lx\n", nonce, nonce, upper, lower,
               device_difficulty_upper, device_difficulty_lower);
        device_found_nonce = nonce;
    }
    else if (device_minor_lower)
    {
#if MINOR
        // do same thing for minor nonce
        found = 0;

        if (device_minor_upper && upper < device_minor_upper)
        {
            found = 1;
        }
        else
        {

            if (device_minor_upper == upper && lower < device_minor_lower)
            {
                found = 1;
            }
        }

        if (found)
        {

            printf("IN: \n0x%016lx%016lx%016lx%016lx\n OUT: \n0x%016lx%016lx%016lx%016lx\n",
                   save_state00,
                   save_state01,
                   save_state02,
                   save_state03,
                   cuda_swab64(state00),
                   cuda_swab64(state01),
                   cuda_swab64(state02),
                   cuda_swab64(state03));
            printf(">>> found minor nonce=%lu/0x%016lx combined=0x%06lx%016lx minor=0x%06lx%016lx\n", nonce, nonce, upper, lower,
                   device_minor_upper, device_minor_lower);
            device_found_minor = nonce;
        }
#endif
    }

    atomicAdd(&device_hash_count, 1);

#if DEBUG
    // printf("device_hash_count=%u\n", device_hash_count);
#endif

    // #if 32 < HASH_SIZE
    //     memcpy(output + (blockIdx.x * BLOCKX + threadIdx.x) * HASH_SIZE + 32, &state04, 8);
    // #endif
}

int Padding(uint8_t input[], int inputByte, uint8_t output[])
{
    int outputByte = R / 8 - (inputByte + 1) % (R / 8) + inputByte + 1;
    log_info("Padding inputByte=%d outputByte=%d\n", inputByte, outputByte);
    memcpy(output, input, inputByte);
    memset(output + inputByte, 0, sizeof(uint8_t) * (outputByte - inputByte));
    output[inputByte] = SUFFIX;
    output[outputByte - 1] ^= 0x80;
    return outputByte;
}

//byte

// uint8_t m[] = {0x22, 0x23, 0x3E, 0x5F, 0xCC, 0x4E, 0xFC, 0x0E, 0xEB, 0x03, 0x0C, 0x72, 0xF9, 0x7A, 0x4E, 0x8A, 0x9D, 0xC4, 0xBB, 0x96, 0x18, 0x33, 0xDA, 0xE8, 0xEF, 0xED, 0xCF, 0xFD, 0xE2, 0xA3, 0xC0, 0x37, 0x00, 0x69, 0xCE, 0x65, 0xB3, 0x32, 0x38, 0xAC, 0x43, 0xD6, 0x47, 0x64, 0xFB, 0xDA, 0xDE, 0xDC, 0x6A, 0x22, 0xA3, 0x0C, 0x15, 0xCC, 0x01, 0x0D, 0x7F, 0xC3, 0xA4, 0x45, 0xE3, 0x5E, 0xDA, 0xB7, 0x69, 0x29, 0xD0, 0xAB, 0x6C, 0x48, 0x35, 0xF2, 0x1F, 0xA7, 0x2D, 0x20, 0xC3, 0x3E, 0x5F, 0xCC, 0x4E, 0xFC, 0x0E, 0xEB, 0x03, 0x0C, 0x72, 0xF9, 0x7A, 0x4E, 0x8A, 0x9D, 0xC4, 0xBB, 0x96, 0x18, 0x33, 0xDA, 0xE8, 0xEF, 0xED, 0xCF, 0xFD, 0xE2, 0xA3, 0xC0, 0x37, 0x00, 0x69, 0xCE, 0x65, 0xB3, 0x32, 0x38, 0xAC, 0x43, 0xD6, 0x47, 0x64, 0xFB, 0xDA, 0xDE, 0xDC};
// uint8_t msg[32] = {0x04, 0x22, 0x00, 0x00, 0x00, 0x00, 0x3B, 0x00, 0x19, 0x00, 0x00, 0x00,
//                  0x7D, 0x43, 0x7E, 0x28, 0xCD, 0x73, 0xA3, 0xF4, 0x87,
//                  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
uint8_t msg[32] = {0};

uint8_t output[BLOCKNUM * BLOCKX][HASH_SIZE];
uint8_t input[BLOCKSIZE];
uint8_t host_input[SUMDATASIZE];

// #define STREAMNUM 5 xxx

cudaStream_t stream[STREAMNUM];
uint32_t *device_input[STREAMNUM];
uint8_t *device_output[STREAMNUM];

uint64_t getTime(void)
{
    uint64_t val = 0;
    struct timeval tv;

    gettimeofday(&tv, NULL);

    val = (((uint64_t)tv.tv_sec) * 1000 + ((uint64_t)tv.tv_usec) / 1000);
    // log_info("getTime tv.tv_sec %ld tv_usec %ld val %ld\n", tv.tv_sec, tv.tv_usec, val);
    return (uint64_t)val;
}

void printMsg(const char *title, uint8_t *msg, int len)
{
    if (title)
    {
        log_info("%s:\n0x", title);
    }
    else
    {
        printf("0x");
    }
    for (int i = 0; i < len; i++)
    {
        printf("%02X", msg[i]);
    }
    printf("\n");
}

void FreeAll()
{
    log_info("freeAll..\n");
    cudaDeviceSynchronize();
    for (int i = 0; i < STREAMNUM; i++)
    {
        cudaStreamDestroy(stream[i]);
        cudaFree(device_input[i]);
        cudaFree(device_output[i]);
    }
}

void checkCUDAError(const char *msg)
{
    cudaError_t err = cudaGetLastError();
    if (cudaSuccess != err)
    {
        log_err("Cuda error : % s : % s.\n ", msg, cudaGetErrorString(err));
        FreeAll();
        exit(EXIT_FAILURE);
    }
}

void setMsg(OPTS *opts)
{

    const char *val;
    int base;
    mpz_t sender_mpz;
    mpz_t lastMinedPunkAsset_mpz;
    mpz_t difficulty_mpz;
    mpz_t startNonce_mpz;
    size_t count;

    if (opts->str_address)
    {
        val = opts->str_address;
    }
    else
    {
        val = DEFAULT_ADDRESS;
    }
    if (val && val[0] == '0' and val[1] == 'x')
    {
        val = val + 2;
        base = 16;
    }
    else
    {
        base = 10;
    }
    mpz_init_set_str(sender_mpz, &val[22], 16);
    gmp_printf("sender_mpz=%Zd/%018Zx\n", sender_mpz, sender_mpz);

    if (opts->str_lastMined)
    {
        val = opts->str_lastMined;
    }
    else
    {
        val = DEFAULT_LASTMINED;
    }
    if (val && val[0] == '0' and val[1] == 'x')
    {
        val = val + 2;
        base = 16;
    }
    else
    {
        base = 10;
    }

    mpz_init_set_str(lastMinedPunkAsset_mpz, val, base);
    gmp_printf("lastMinedPunkAsset_mpz=%Zd/0x%Zx\n", lastMinedPunkAsset_mpz, lastMinedPunkAsset_mpz);

    if (opts->str_startNonce)
    {
        val = opts->str_startNonce;
    }
    else
    {
        val = NULL;
    }

    if (val && val[0] == '0' and val[1] == 'x')
    {
        val = val + 2;
        base = 16;
    }
    else
    {
        base = 10;
    }

    if (val)
    {
        mpz_init_set_str(startNonce_mpz, val, base);
        gmp_printf("startNonce_mpz=%Zd/0x%Zx\n", startNonce_mpz, startNonce_mpz);
        mpz_export(&opts->startNonce, &count, 1, sizeof(opts->startNonce), 0, 0, startNonce_mpz);
    }

    if (opts->str_difficulty)
    {
        val = opts->str_difficulty;
    }
    else
    {
        val = DEFAULT_DIFFICULTY;
    }

    if (val && val[0] == '0' and val[1] == 'x')
    {
        val = val + 2;
        base = 16;
    }
    else
    {
        base = 10;
    }

    uint8_t difficulty[16];
    if (val)
    {
        mpz_init_set_str(difficulty_mpz, val, base);
        gmp_printf("difficulty_mpz=%Zd/0x%032Zx\n", difficulty_mpz, difficulty_mpz);
        mpz_export(difficulty, &count, 1, sizeof(difficulty), 0, 0, difficulty_mpz);

        opts->upper_difficulty = ((uint64_t *)difficulty)[1];
        opts->lower_difficulty = ((uint64_t *)difficulty)[0];
    }
    // printMsg("difficulty", difficulty, 16);

    // log_info("0x%016lx %016lx\n", opts->upper_difficulty, opts->lower_difficulty);

    if (opts->str_minor)
    {
        val = opts->str_minor;
    }
    else
    {
        val = DEFAULT_MINOR;
    }

    if (val && val[0] == '0' and val[1] == 'x')
    {
        val = val + 2;
        base = 16;
    }
    else
    {
        base = 10;
    }

    if (val)
    {
        mpz_init_set_str(difficulty_mpz, val, base);
        gmp_printf("minor difficulty_mpz=%Zd/0x%032Zx\n", difficulty_mpz, difficulty_mpz);
        mpz_export(difficulty, &count, 1, sizeof(difficulty), 0, 0, difficulty_mpz);

        opts->upper_minor = ((uint64_t *)difficulty)[1];
        opts->lower_minor = ((uint64_t *)difficulty)[0];
    }
    // printMsg("difficulty", difficulty, 16);

    /* set msg */
    printMsg("pre msg", msg, 32);
    mpz_export(msg, &count, 1, 12, 1, 0, lastMinedPunkAsset_mpz);
    mpz_export(msg + 12, &count, 1, 9, 1, 0, sender_mpz);
    printMsg("pos msg", msg, 32);

    Padding(msg, sizeof(msg), input);
    for (int i = 0; i < STREAMNUM; i++)
    {
        cudaStreamCreate(&stream[i]);
    }
    checkCUDAError("create stream error");
    log_info("init.. writing %d blocks size_t=%d\n", BLOCKX * BLOCKNUM, BLOCKSIZE);
    for (int i = 0; i < BLOCKX * BLOCKNUM; i++)
    {
        memcpy(host_input + i * BLOCKSIZE, input, BLOCKSIZE);
        // printMsg("msg",host_input + i*BLOCKSIZE, 32);

        // break;
    }

    cudaMemcpyToSymbol(device_difficulty_lower, &opts->lower_difficulty, sizeof(opts->lower_difficulty), 0, cudaMemcpyHostToDevice);
    checkCUDAError("copy to symbol");
    cudaMemcpyToSymbol(device_difficulty_upper, &opts->upper_difficulty, sizeof(opts->upper_difficulty), 0, cudaMemcpyHostToDevice);
    checkCUDAError("copy to symbol");

    cudaMemcpyToSymbol(device_minor_lower, &opts->lower_minor, sizeof(opts->lower_minor), 0, cudaMemcpyHostToDevice);
    checkCUDAError("copy to symbol");
    cudaMemcpyToSymbol(device_minor_upper, &opts->upper_minor, sizeof(opts->upper_minor), 0, cudaMemcpyHostToDevice);
    checkCUDAError("copy to symbol");
}

void GetCudaMalloc(int length)
{
    for (int i = 0; i < STREAMNUM; i++)
    {
        cudaMalloc(&device_input[i], BLOCKNUM * BLOCKX * BLOCKSIZE);
        checkCUDAError("malloc for device_input");
        cudaMalloc(&device_output[i], BLOCKX * BLOCKNUM * HASH_SIZE);
        checkCUDAError("malloc for device_output");
    }
}

static int destructing = 0;
void destruct()
{
    log_info("destruct..\n");
    if (destructing)
    {
        return;
    }
    destructing = 1;
}

/* Signal Handler for SIGINT */
void sigintHandler(int sig_num)
{
    log_info("caught signal: SIGINT\n");

    destruct();
}

/* Signal Handler for SIGTERM */
void sigtermHandler(int sig_num)
{
    log_info("caught signal: SIGTERM\n");
    destruct();
}

void get_options(int argc, char **argv, OPTS *opts)
{
    int c;

    memset(opts, 0, sizeof(OPTS));

    opts->controller = DEFAULT_CONTROLLER;
    opts->str_address = strdup(DEFAULT_ADDRESS);
    opts->start_address = strdup(DEFAULT_ADDRESS);
    opts->str_difficulty = strdup(DEFAULT_DIFFICULTY);
    opts->str_lastMined = strdup(DEFAULT_LASTMINED);

    static struct option long_options[] =
        {
            {"address", required_argument, 0, 'a'},
            {"difficulty", required_argument, 0, 'd'},
            {"startNonce", required_argument, 0, 's'},
            {"lastMined", required_argument, 0, 'l'},
            {"cudaDevice", required_argument, 0, 'x'},
            {"testing", no_argument, 0, 't'},
            {"user controller flag", optional_argument, 0, 'c'},
            {"version", no_argument, 0, 'v'},
            {"help", no_argument, 0, 'h'},
            {0, 0, 0, 0}};

#if FULL
#else
    opts->use_controller = true;
#endif

    while (1)
    {
        int option_index = 0;

        c = getopt_long(argc, argv, "a:d:s:l:x:tc::vh", long_options, &option_index);

        /* Detect the end of the options. */
        if (c == -1)
            break;

        switch (c)
        {
        case '0':
            log_info("have 0\n");
            break;
        case 'a':
#if FULL
#else
            free(opts->str_address);
            opts->str_address = strdup(optarg);
#endif
            free(opts->start_address);
            opts->start_address = strdup(optarg);
            log_info("opt address='%s'\n", opts->str_address);
            break;
        case 'd':
            free(opts->str_difficulty);
            opts->str_difficulty = strdup(optarg);
            log_info("opt difficulty='%s'\n", opts->str_difficulty);
            break;
        case 's':
            free(opts->str_startNonce);
            opts->str_startNonce = strdup(optarg);
            log_info("opt startNonce='%s'\n", opts->str_startNonce);
            break;
        case 'l':
            free(opts->str_lastMined);
            opts->str_lastMined = strdup(optarg);
            log_info("opt lastMined='%s'\n", opts->str_lastMined);
            break;
        case 'x':
            opts->device = atoi(optarg);
            log_info("opt device='%d'\n", opts->device);
            break;
        case 't':
            opts->test = true;
            log_info("opt test only\n");
            break;
        case 'c':
            opts->use_controller = true;
#if FULL
            if (optarg) // XXX
            {
                opts->controller = strdup(optarg);
            }
            log_info("use controller=%s\n", opts->controller);
#endif
            break;
        case 'v':
            printf("version=%s\n", VERSION);
            exit(0);
        default:
            log_info("option `%c` is not supported.\n", c);
            exit(0);
        }
    }
}

struct MemoryStruct
{
    char *memory;
    size_t size;
};

size_t
getCurlData(void *contents, size_t size, size_t nmemb, void *userp)
{
    size_t realsize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *)userp;
    mem->memory = (char *)realloc(mem->memory, mem->size + realsize + 1);
    if (mem->memory == NULL)
    {
        /* out of memory! */
        log_err("not enough memory (realloc returned NULL)\n");
        return 0;
    }
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;
    return realsize;
}

bool json_setValue(char **place, json_t *payload, const char *name, bool *changed)
{

    json_t *value = json_object_get(payload, name);
    if (!value)
    {
        log_info("error unable to get %s.\n", name);
        return false;
    }

    json_auto_t *compare = json_string(*place);

    if (!json_equal(compare, value))
    {
        *changed = true;
    }

    // log_info("%p\n", *place);

    if (*changed)
    {
        free(*place);
        *place = strdup((char *)json_string_value(value));
        log_info("controller setting %s=%s\n", name, *place);
    }

    json_decref(compare);

    return true;
}

bool submitNonce(OPTS *opts, uint64_t nonce, bool minor)
{

    if (destructing)
        return false;

    CURL *curl;
    CURLcode res;
    // bool success = false;

    log_info("submitNonce.. nonce=%lx\n", nonce);

    curl = curl_easy_init();

    struct MemoryStruct chunk;
    chunk.memory = NULL;
    chunk.size = 0;
    chunk.memory = (char *)malloc(1);

    char url[256];
    const char *address = opts->str_address;
    if (!address)
    {
        address = DEFAULT_ADDRESS;
    }

    if (minor == true)
    {
        sprintf(url, "%s/submit-ping?nonce=%lu&address=%s&last=%s&src=%s", opts->controller, nonce, address, opts->str_lastMined,
                opts->start_address);
    }
    else
    {
        sprintf(url, "%s/submit-work?nonce=%lu&address=%s&last=%s&src=%s", opts->controller, nonce, address, opts->str_lastMined,
                opts->start_address);
    }
    log_sensitive("url=%s\n", url);

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, getCurlData);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
    res = curl_easy_perform(curl);
    if (res != CURLE_OK)
    {
        log_err("curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        if (chunk.memory)
        {
            free(chunk.memory);
        }
        curl_easy_cleanup(curl);
        return false;
    }

    if (!chunk.memory)
    {
        log_info("chunk memory is null\n");
        curl_easy_cleanup(curl);
        return false;
    }

    log_info("response: %s\n", chunk.memory);
    free(chunk.memory);
    curl_easy_cleanup(curl);
    return true;
}

bool submitMinor(OPTS *opts, uint64_t nonce)
{
    log_info("submitMinor..\n");
    return submitNonce(opts, nonce, true);
}

bool heartbeat(OPTS *opts, uint32_t hash_rate)
{
    if (destructing)
        return false;

    CURL *curl;
    CURLcode res;
    // bool success = false;

    log_info("heartbeat.. hash_rate=%u\n", hash_rate);

    curl = curl_easy_init();

    struct MemoryStruct chunk;
    chunk.memory = NULL;
    chunk.size = 0;
    chunk.memory = (char *)malloc(1);

    char url[256];
    const char *address = opts->str_address;
    if (!address)
    {
        address = DEFAULT_ADDRESS;
    }
    sprintf(url, "%s/heartbeat?hashrate=%u&address=%s&src=%s", opts->controller, hash_rate, address, opts->start_address);

    log_sensitive("url=%s\n", url);

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, getCurlData);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
    res = curl_easy_perform(curl);
    if (res != CURLE_OK)
    {
        log_err("curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        if (chunk.memory)
        {
            free(chunk.memory);
        }
        curl_easy_cleanup(curl);
        return false;
    }

    if (!chunk.memory)
    {
        log_info("chunk memory is null\n");
        curl_easy_cleanup(curl);
        return false;
    }

    free(chunk.memory);
    curl_easy_cleanup(curl);
    return true;
}

bool getMiningInputs(OPTS *opts)
{

    if (destructing)
        return false;

    CURL *curl;
    CURLcode res;
    bool success = false;

    log_info("getMiningInputs..\n");

    curl = curl_easy_init();

    struct MemoryStruct chunk;
    chunk.memory = NULL;
    chunk.size = 0;
    chunk.memory = (char *)malloc(1);

    char url[256];
    const char *address = opts->str_address;
    if (!address)
    {
        address = DEFAULT_ADDRESS;
    }
    sprintf(url, "%s/mining-inputs?address=%s", opts->controller, address);

    log_sensitive("url=%s\n", url);

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, getCurlData);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
    res = curl_easy_perform(curl);
    if (res != CURLE_OK)
    {
        log_err("curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        if (chunk.memory)
        {
            free(chunk.memory);
        }
        return false;
    }

    if (!chunk.memory)
    {
        log_info("chunk memory is null\n");
        curl_easy_cleanup(curl);
        return false;
    }

    json_error_t error;
    json_t *root;

    root = json_loads(chunk.memory, 0, &error);
    if (!root)
    {
        log_info("error loading json %s\n", error.text);
        log_info("data %s\n", chunk.memory);
        if (chunk.memory)
        {
            free(chunk.memory);
        }
        curl_easy_cleanup(curl);
        return false;
    }
    else
    {
        json_t *value = json_object_get(root, "status");
        json_auto_t *compare = json_string("success");
        if (!json_equal(value, compare))
        {
            log_info("not successful %s\n", chunk.memory);
            json_decref(root);
            json_decref(compare);
            goto end;
        }
        json_decref(compare);

        json_t *payload = json_object_get(root, "payload");
        if (!payload)
        {
            log_info("unable to get payload. %s\n", chunk.memory);
            json_decref(root);
            goto end;
        }

        bool changed = 0;
        success = json_setValue(&opts->str_lastMined, payload, "lastMinedAssets", &changed);
        if (!success)
        {
            log_info("error data: %s\n", chunk.memory);
            json_decref(root);
            goto end;
        }

        success = json_setValue(&opts->str_address, payload, "senderAddress", &changed);
        if (!success)
        {
            log_info("error data: %s\n", chunk.memory);
            json_decref(root);
            goto end;
        }

        success = json_setValue(&opts->str_difficulty, payload, "difficultyTarget", &changed);
        if (!success)
        {
            log_info("error data: %s\n", chunk.memory);
            json_decref(root);
            goto end;
        }

        success = json_setValue(&opts->str_minor, payload, "minorDifficulty", &changed);
        if (!success)
        {
            log_info("error data: %s\n", chunk.memory);
            json_decref(root);
            goto end;
        }

        opts->values_changed = changed;

        json_decref(root);
    }
end:
    if (chunk.memory)
    {
        free(chunk.memory);
    }
    curl_easy_cleanup(curl);
    return success;
}

int main(int argc, char **argv)
{
    log_info("Hi There!!\n");

    /* xxx random number */
    time_t t;
    srand((unsigned)time(&t) + (unsigned)getpid());

    signal(SIGINT, sigintHandler);
    signal(SIGTERM, sigtermHandler);

    OPTS opts;
    get_options(argc, argv, &opts);

    if (opts.use_controller)
    {
        getMiningInputs(&opts);
    }

    log_info("using device %d\n.", opts.device);
    cudaSetDevice(opts.device);
    checkCUDAError("set device");

    int minGridSize, blockSize;
    cudaOccupancyMaxPotentialBlockSize(&minGridSize, &blockSize, Keccak1600, BLOCKSIZE, 0);
    log_info("recomminding blockSize=%d gridSize=%d\n", minGridSize, blockSize);

    // opts.block_size = blockSize;
    // opts.grid_size = minGridSize;

    if (opts.test)
    {
        return 0;
    }
    GetCudaMalloc(BLOCKSIZE);

    timeval tpstart;

    log_info("CUDA start\n");
    int cur = 0;
    gettimeofday(&tpstart, NULL);
    // double all_sec = 0;
    uint64_t start = getTime();
    uint64_t tstart = start;
    uint64_t elapsed = 0;
    uint32_t n_hashes = 0;
    uint32_t hash_count = 0;
    uint32_t hash_rate = 0;

    uint64_t found_nonce = 0;
    uint64_t found_minor = 0;

    int n_secs = 0;

    cudaEvent_t cuda_start, cuda_stop;

    setMsg(&opts);
    for (int i = 0; i < STREAMNUM; i++)
    {
        cudaMemcpyAsync(device_input[i], host_input, SUMDATASIZE, cudaMemcpyHostToDevice, stream[i]);
        checkCUDAError("memcpy from buf to device_input");
    }

    uint64_t startNonce;
    int run = 0;
#if DEBUG
    if (opts.str_startNonce)
    {
        startNonce = opts.startNonce;
    }
    else
    {
        startNonce = 609667058559510624;
    }

    for (int i = 0; i < 3; i++)
#else
    if (opts.str_startNonce)
    {
        startNonce = opts.startNonce;
    }
    else
    {
        startNonce = rand_uint64();
    }
    // startNonce = 609667058559510630;
    while (!destructing)
    // for (int i = 0; i < 2; i++)
#endif
    {

#if DEBUG
        log_info("%s run=%d startNonce=%lu/0x%016lx ->>\n", ctime(&t), run, startNonce, startNonce);
#endif

        cudaBindTexture(0, texreference_input, device_input[cur], SUMDATASIZE);

        cudaEventCreate(&cuda_start);
        cudaEventCreate(&cuda_stop);
        cudaEventRecord(cuda_start, 0);

        Keccak1600<<<BLOCKNUM, BLOCKX, 0, stream[cur]>>>(BLOCKSIZE / 4, device_output[cur], HASH_SIZE, startNonce);

        cudaEventRecord(cuda_stop, 0);
        cudaEventSynchronize(cuda_stop);

        float elapsedTime = 0.0;
        cudaEventElapsedTime(&elapsedTime, cuda_start, cuda_stop);
        cudaMemcpyFromSymbol(&hash_count, device_hash_count, sizeof(hash_count), 0, cudaMemcpyDeviceToHost);
        cudaMemcpyFromSymbol(&found_nonce, device_found_nonce, sizeof(found_nonce), 0, cudaMemcpyDeviceToHost);
        cudaMemcpyFromSymbol(&found_minor, device_found_minor, sizeof(found_minor), 0, cudaMemcpyDeviceToHost);
        // log_info("device took %fms for %u hashes\n", elapsedTime, hash_count);

        cudaEventDestroy(cuda_start);
        cudaEventDestroy(cuda_stop);

        cur = (cur + 1) % STREAMNUM;
        cudaUnbindTexture(&texreference_input);

        // log_info("hash_count=%d\n", hash_count);

        if (found_nonce)
        {
            log_info(">>>>>>>>>>>found_nonce=%lu\n", found_nonce);
            submitNonce(&opts, found_nonce, false);
            found_nonce = 0;
            cudaMemcpyToSymbol(device_found_nonce, &found_nonce, sizeof(found_nonce), 0, cudaMemcpyHostToDevice);
        }

        if (found_minor)
        {
            log_info(">>>>>>>>>>>found_minor=%lu\n", found_minor);
            submitMinor(&opts, found_minor);
            found_minor = 0;
            cudaMemcpyToSymbol(device_found_minor, &found_minor, sizeof(found_minor), 0, cudaMemcpyHostToDevice);
        }

        // hash_count = BLOCKX * BLOCKNUM;

        startNonce += hash_count;
        n_hashes += hash_count;
        hash_count = 0;
        cudaMemcpyToSymbol(device_hash_count, &hash_count, sizeof(hash_count), 0, cudaMemcpyHostToDevice);

        elapsed = getTime() - tstart;
        if (elapsed > 1000)
        {
            hash_rate = (n_hashes / elapsed) * 1000;
            log_info(">>> STATS.. nhashes=%u/s n_secs=%ds nonce=%lu\n", hash_rate, n_secs, startNonce);
            n_hashes = 0;
            tstart = getTime();
            n_secs++;
        }

        if (n_secs > POLL_TIME && !destructing && opts.use_controller)
        {
            heartbeat(&opts, hash_rate);
            bool success = getMiningInputs(&opts);
            if (opts.values_changed)
            {
                setMsg(&opts);
                for (int i = 0; i < STREAMNUM; i++)
                {
                    cudaMemcpyAsync(device_input[i], host_input, SUMDATASIZE, cudaMemcpyHostToDevice, stream[i]);
                    checkCUDAError("memcpy from buf to device_input");
                }

                opts.values_changed = 0;
            }
            n_secs = 0;
        }

        run++;
        fflush(stdout);
    }
    FreeAll();
    log_info("END\n");

    return 0;
}
