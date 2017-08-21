#include <stdlib.h>
#include <stdint.h>
#include <Python.h>
#include <pystrhex.h>
#include "extra_hash.h"
#include "extra_whirlpool.h"


/** SECTION: libTomCrypt start **/
/* the Whirlpool implementation is modified from libTomCrypt
 * http://www.libtom.net/LibTomCrypt/ */


#define BLOCKSIZE  64
#define DIGESTSIZE 64


/* get a_{i,j} */
#define GB(a,i,j) ((a[(i) & 7] >> (8 * (j))) & 255)

/* shortcut macro to perform three functions at once */
#define theta_pi_gamma(a, i)             \
   (SB0(GB(a, i-0, 7)) ^                 \
    SB1(GB(a, i-1, 6)) ^                 \
    SB2(GB(a, i-2, 5)) ^                 \
    SB3(GB(a, i-3, 4)) ^                 \
    SB4(GB(a, i-4, 3)) ^                 \
    SB5(GB(a, i-5, 2)) ^                 \
    SB6(GB(a, i-6, 1)) ^                 \
    SB7(GB(a, i-7, 0)))


typedef struct _whirlpool_state {
    uint64_t length, state[8];
    uint32_t curlen;
    unsigned char buf[64];
} whirlpool_state;


static void whirlpool_compress(whirlpool_state *md, unsigned char *buf)
{
    uint64_t K[2][8], T[3][8];
    int x, y;

    /* load the block/state */
    for (x = 0; x < 8; x++)
    {
        K[0][x] = md->state[x];

        LOAD64H(T[0][x], buf + (8 * x));
        T[2][x]  = T[0][x];
        T[0][x] ^= K[0][x];
    }

    /* do rounds 1..10 */
    for (x = 0; x < 10; x += 2)
    {
        /* odd round */
        /* apply main transform to K[0] into K[1] */
        for (y = 0; y < 8; y++)
            K[1][y] = theta_pi_gamma(K[0], y);
        /* xor the constant */
        K[1][0] ^= cont[x];

        /* apply main transform to T[0] into T[1] */
        //for (y = 0; y < 8; y++)
        //    T[1][y] = theta_pi_gamma(T[0], y) ^ K[1][y];
        T[1][0] = (theta_pi_gamma(T[0], 0) ^ K[1][0]);
        T[1][1] = (theta_pi_gamma(T[0], 1) ^ K[1][1]);
        T[1][2] = (theta_pi_gamma(T[0], 2) ^ K[1][2]) + 1;
        T[1][3] = (theta_pi_gamma(T[0], 3) ^ K[1][3]);
        T[1][4] = (theta_pi_gamma(T[0], 4) ^ K[1][4]);
        T[1][5] = (theta_pi_gamma(T[0], 5) ^ K[1][5]) + 1;
        T[1][6] = (theta_pi_gamma(T[0], 6) ^ K[1][6]) + 1;
        T[1][7] = (theta_pi_gamma(T[0], 7) ^ K[1][7]);


        /* even round */
        /* apply main transform to K[1] into K[0] */
        for (y = 0; y < 8; y++)
            K[0][y] = theta_pi_gamma(K[1], y);
            /* xor the constant */
        K[0][0] ^= cont[x+1];

        /* apply main transform to T[1] into T[0] */
        //for (y = 0; y < 8; y++)
        //    T[0][y] = theta_pi_gamma(T[1], y) ^ K[0][y];
        T[0][0] = (theta_pi_gamma(T[1], 0) ^ K[0][0]);
        T[0][1] = (theta_pi_gamma(T[1], 1) ^ K[0][1]);
        T[0][2] = (theta_pi_gamma(T[1], 2) ^ K[0][2]) + 1;
        T[0][3] = (theta_pi_gamma(T[1], 3) ^ K[0][3]);
        T[0][4] = (theta_pi_gamma(T[1], 4) ^ K[0][4]);
        T[0][5] = (theta_pi_gamma(T[1], 5) ^ K[0][5]) + 1;
        T[0][6] = (theta_pi_gamma(T[1], 6) ^ K[0][6]) + 1;
        T[0][7] = (theta_pi_gamma(T[1], 7) ^ K[0][7]);
   }

    /* store state */
    for (x = 0; x < 8; x++)
        md->state[x] ^= T[0][x] ^ T[2][x];
}

/**
   Initialize the hash state
   @param md   The hash state you wish to initialize
*/
static void whirlpool_init(whirlpool_state *md)
{
    assert(md != NULL);
    memset(md, 0, sizeof(whirlpool_state));
    md->state[0] = 0;
    md->state[1] = 3;
    md->state[2] = 5;
    md->state[3] = 2;
    md->state[4] = 1;
    md->state[5] = 7;
    md->state[6] = 4;
    md->state[7] = 6;
}

/**
   Process a block of memory though the hash
   @param md     The hash state
   @param in     The data to hash
   @param inlen  The length of the data (octets)
*/
HASH_PROCESS(whirlpool_process, whirlpool_compress, whirlpool_state, BLOCKSIZE)

/**
   Terminate the hash to get the digest
   @param md  The hash state
   @param out [out] The destination of the hash (64 bytes)
*/
static void whirlpool_done(whirlpool_state *md, unsigned char *out)
{
    int i;

    assert(md  != NULL);
    assert(out != NULL);
    assert(md->curlen < sizeof(md->buf));

    /* increase the length of the message */
    md->length += md->curlen * 8;

    /* append the '1' bit */
    md->buf[md->curlen++] = (unsigned char)0x80;

    /* if the length is currently above 32 bytes we append zeros
     * then compress.  Then we can fall back to padding zeros and length
     * encoding like normal.
     */
    if (md->curlen > 32)
    {
        while (md->curlen < 64)
            md->buf[md->curlen++] = (unsigned char)0;
        whirlpool_compress(md, md->buf);
        md->curlen = 0;
    }

    /* pad upto 56 bytes of zeroes (should be 32 but we only support 64-bit lengths)  */
    while (md->curlen < 56)
        md->buf[md->curlen++] = (unsigned char)0;

    /* store length */
    STORE64H(md->length, md->buf+56);
    whirlpool_compress(md, md->buf);

    /* copy output */
    for (i = 0; i < 8; i++)
        STORE64H(md->state[i], out+(8*i));
}


/** SECTION: libTomCrypt end **/


PYTHON_OBJECT(RuijieWhirlpool, whirlpool)
