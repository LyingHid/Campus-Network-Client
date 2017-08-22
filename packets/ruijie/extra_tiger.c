#include "extra_hash.h"
#include "extra_tiger.h"


/** SECTION: libTomCrypt start **/
/* the MD5 implementation is modified from libTomCrypt
 * http://www.libtom.net/LibTomCrypt/ */


#define BLOCKSIZE  64
#define DIGESTSIZE 24


typedef struct _tiger_state {
    uint64_t state[3], length;
    unsigned long curlen;
    unsigned char buf[64];
} tiger_state;


/* one round of the hash function */
inline static void tiger_round(uint64_t *a, uint64_t *b, uint64_t *c, uint64_t x, int mul)
{
    uint64_t tmp;
    tmp = (*c ^= x);
           *a -= t1[byte(tmp, 0)] ^ t2[byte(tmp, 2)] ^ t3[byte(tmp, 4)] ^ t4[byte(tmp, 6)];
    tmp = (*b += t4[byte(tmp, 1)] ^ t3[byte(tmp, 3)] ^ t2[byte(tmp,5)] ^ t1[byte(tmp,7)]);
    switch (mul) {
        case 5:  *b = (tmp << 2) + tmp; break;
        case 7:  *b = (tmp << 3) - tmp; break;
        case 9:  *b = (tmp << 3) + tmp; break;
    }
}

/* one complete pass */
static void pass(uint64_t *a, uint64_t *b, uint64_t *c, uint64_t *x, int mul)
{
    tiger_round(a,b,c,x[0],mul);
    tiger_round(b,c,a,x[1],mul);
    tiger_round(c,a,b,x[2],mul);
    tiger_round(a,b,c,x[3],mul);
    tiger_round(b,c,a,x[4],mul);
    tiger_round(c,a,b,x[5],mul);
    tiger_round(a,b,c,x[6],mul);
    tiger_round(b,c,a,x[7],mul);
}

/* The key mixing schedule */
static void key_schedule(uint64_t *x)
{
    //x[0] -= x[7] ^ CONST64(0xA5A5A5A5A5A5A5A5);
    x[0] -= x[7] ^ CONST64(0xA5A5B5A5A5A5A7A5);
    x[1] ^= x[0];
    x[2] += x[1];
    x[3] -= x[2] ^ ((~x[1])<<19);
    x[4] ^= x[3];
    x[5] += x[4];
    x[6] -= x[5] ^ ((~x[4])>>23);
    x[7] ^= x[6];
    x[0] += x[7];
    x[1] -= x[0] ^ ((~x[7])<<19);
    x[2] ^= x[1];
    x[3] += x[2];
    x[4] -= x[3] ^ ((~x[2])>>23);
    x[5] ^= x[4];
    x[6] += x[5];
    x[7] -= x[6] ^ CONST64(0x0123456789ABCDEF);
}

static void tiger_compress(tiger_state *md, unsigned char *buf)
{
    uint64_t a, b, c, x[8];
    unsigned long i;

    /* load words */
    for (i = 0; i < 8; i++) {
        LOAD64L(x[i],&buf[8*i]);
    }
    a = md->state[0];
    b = md->state[1];
    c = md->state[2];

    pass(&a,&b,&c,x,5);
    key_schedule(x);
    pass(&c,&a,&b,x,7);
    key_schedule(x);
    pass(&b,&c,&a,x,9);

    /* store state */
    md->state[0] = a ^ md->state[0];
    md->state[1] = b - md->state[1];
    md->state[2] = c + md->state[2];
}

/**
   Initialize the hash state
   @param md   The hash state you wish to initialize
*/
static void tiger_init(tiger_state *md)
{
    assert(md != NULL);
    //md->state[0] = CONST64(0x0123456789ABCDEF);
    //md->state[1] = CONST64(0xFEDCBA9876543210);
    //md->state[2] = CONST64(0xF096A5B4C3B2E187);
    md->state[0] = CONST64(0x158e427ac96b03df);
    md->state[1] = CONST64(0xf025c13b8e9da784);
    md->state[2] = CONST64(0xb690ab45c3e21b74);
    md->curlen = 0;
    md->length = 0;
}

/**
   Process a block of memory though the hash
   @param md     The hash state
   @param in     The data to hash
   @param inlen  The length of the data (octets)
*/
HASH_PROCESS(tiger_process, tiger_compress, tiger_state, BLOCKSIZE)

/**
   Terminate the hash to get the digest
   @param md  The hash state
   @param out [out] The destination of the hash (24 bytes)
*/
static void tiger_done(tiger_state *md, unsigned char *out)
{
    assert(md  != NULL);
    assert(out != NULL);
    assert(md->curlen < sizeof(md->buf));

    /* increase the length of the message */
    md->length += md->curlen * 8;

    /* append the '1' bit */
    md->buf[md->curlen++] = (unsigned char)0x01;

    /* if the length is currently above 56 bytes we append zeros
     * then compress.  Then we can fall back to padding zeros and length
     * encoding like normal. */
    if (md->curlen > 56) {
        while (md->curlen < 64) {
            md->buf[md->curlen++] = (unsigned char)0;
        }
        tiger_compress(md, md->buf);
        md->curlen = 0;
    }

    /* pad upto 56 bytes of zeroes */
    while (md->curlen < 56) {
        md->buf[md->curlen++] = (unsigned char)0;
    }

    /* store length */
    STORE64L(md->length, md->buf+56);
    tiger_compress(md, md->buf);

    /* copy output */
    STORE64L(md->state[0], &out[0]);
    STORE64L(md->state[1], &out[8]);
    STORE64L(md->state[2], &out[16]);
}


/** SECTION: libTomCrypt end **/


PYTHON_OBJECT(RuijieTiger, tiger)
