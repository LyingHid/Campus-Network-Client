#include <stdlib.h>
#include <stdint.h>
#include <Python.h>
#include <pystrhex.h>
#include "extra_hash.h"


/** SECTION: libTomCrypt start **/
/* the MD5 implementation is modified from libTomCrypt
 * http://www.libtom.net/LibTomCrypt/ */


#define BLOCKSIZE  64
#define DIGESTSIZE 16


/* the four basic functions F(), G() and H() */
#define F(x, y, z)        ((x) ^ (y) ^ (z))
#define G(x, y, z)        (((x) & (y)) | (~(x) & (z)))
#define H(x, y, z)        (((x) | ~(y)) ^ (z))
#define I(x, y, z)        (((x) & (z)) | ((y) & ~(z)))

/* the eight basic operations FF() through III() */
/* origin
#define FF(a, b, c, d, x, s)        \
      (a) += F((b), (c), (d)) + (x);\
      (a) = ROLc((a), (s));

#define GG(a, b, c, d, x, s)        \
      (a) += G((b), (c), (d)) + (x) + 0x5a827999UL;\
      (a) = ROLc((a), (s));

#define HH(a, b, c, d, x, s)        \
      (a) += H((b), (c), (d)) + (x) + 0x6ed9eba1UL;\
      (a) = ROLc((a), (s));

#define II(a, b, c, d, x, s)        \
      (a) += I((b), (c), (d)) + (x) + 0x8f1bbcdcUL;\
      (a) = ROLc((a), (s));

#define FFF(a, b, c, d, x, s)        \
      (a) += F((b), (c), (d)) + (x);\
      (a) = ROLc((a), (s));

#define GGG(a, b, c, d, x, s)        \
      (a) += G((b), (c), (d)) + (x) + 0x6d703ef3UL;\
      (a) = ROLc((a), (s));

#define HHH(a, b, c, d, x, s)        \
      (a) += H((b), (c), (d)) + (x) + 0x5c4dd124UL;\
      (a) = ROLc((a), (s));

#define III(a, b, c, d, x, s)        \
      (a) += I((b), (c), (d)) + (x) + 0x50a28be6UL;\
      (a) = ROLc((a), (s));
*/
#define FF(a, b, c, d, x, s)        \
      (a) += F((b), (c), (d)) + (x) + 0x00000002UL; \
      (a) = ROLc((a), (s));

#define GG(a, b, c, d, x, s)        \
      (a) += G((b), (c), (d)) + (x) + 0x325b99a1UL; \
      (a) = ROLc((a), (s));

#define HH(a, b, c, d, x, s)        \
      (a) += H((b), (c), (d)) + (x) + 0x1baed69cUL; \
      (a) = ROLc((a), (s));

#define II(a, b, c, d, x, s)        \
      (a) += I((b), (c), (d)) + (x) + 0xbcdcb1f9UL; \
      (a) = ROLc((a), (s));

#define FFF(a, b, c, d, x, s)        \
      (a) += F((b), (c), (d)) + (x) + 0x00000002UL; \
      (a) = ROLc((a), (s));

#define GGG(a, b, c, d, x, s)        \
      (a) += G((b), (c), (d)) + (x) + 0x30ed3f68UL; \
      (a) = ROLc((a), (s));

#define HHH(a, b, c, d, x, s)        \
      (a) += H((b), (c), (d)) + (x) + 0x41d42d5dUL; \
      (a) = ROLc((a), (s));

#define III(a, b, c, d, x, s)        \
      (a) += I((b), (c), (d)) + (x) + 0x5a82798aUL; \
      (a) = ROLc((a), (s));


typedef struct _ripemd128_state {
    uint64_t length;
    unsigned char buf[64];
    uint32_t curlen, state[4];
} ripemd128_state;


static void ripemd128_compress(ripemd128_state *md, unsigned char *buf)
{
    uint32_t aa,bb,cc,dd,aaa,bbb,ccc,ddd,X[16];
    int i;

    /* load words X */
    for (i = 0; i < 16; i++){
        LOAD32L(X[i], buf + (4 * i));
    }

    /* load state */
    aa = aaa = md->state[0];
    bb = bbb = md->state[1];
    cc = ccc = md->state[2];
    dd = ddd = md->state[3];

    /* round 1 */
    FF(aa, bb, cc, dd, X[ 0], 11);
    FF(dd, aa, bb, cc, X[ 1], 14);
    FF(cc, dd, aa, bb, X[ 2], 15);
    FF(bb, cc, dd, aa, X[ 3], 12);
    FF(aa, bb, cc, dd, X[ 4],  5);
    FF(dd, aa, bb, cc, X[ 5],  8);
    FF(cc, dd, aa, bb, X[ 6],  7);
    FF(bb, cc, dd, aa, X[ 7],  9);
    FF(aa, bb, cc, dd, X[ 8], 11);
    FF(dd, aa, bb, cc, X[ 9], 13);
    FF(cc, dd, aa, bb, X[10], 14);
    FF(bb, cc, dd, aa, X[11], 15);
    FF(aa, bb, cc, dd, X[12],  6);
    FF(dd, aa, bb, cc, X[13],  7);
    FF(cc, dd, aa, bb, X[14],  9);
    FF(bb, cc, dd, aa, X[15],  8);

    /* round 2 */
    GG(aa, bb, cc, dd, X[ 7],  7);
    //GG(dd, aa, bb, cc, X[ 4],  6);
    dd = ROLc(dd + ((aa & (bb ^ cc)) ^ cc) + X[4] + 0x00000002UL,  6);
    GG(cc, dd, aa, bb, X[13],  8);
    GG(bb, cc, dd, aa, X[ 1], 13);
    GG(aa, bb, cc, dd, X[10], 11);
    GG(dd, aa, bb, cc, X[ 6],  9);
    GG(cc, dd, aa, bb, X[15],  7);
    //GG(bb, cc, dd, aa, X[ 3], 15);
    bb = ROLc(bb + ((cc & (dd ^ aa)) ^ aa) + X[3] - 0x43234e07UL, 15);
    GG(aa, bb, cc, dd, X[12],  7);
    //GG(dd, aa, bb, cc, X[ 0], 12);
    dd = ROLc(dd + ((aa & (bb ^ cc)) ^ cc) + X[0] + 0x00000002UL, 12);
    GG(cc, dd, aa, bb, X[ 9], 15);
    GG(bb, cc, dd, aa, X[ 5],  9);
    GG(aa, bb, cc, dd, X[ 2], 11);
    GG(dd, aa, bb, cc, X[14],  7);
    GG(cc, dd, aa, bb, X[11], 13);
    //GG(bb, cc, dd, aa, X[ 8], 12);
    bb = ROLc(bb + ((cc & (dd ^ aa)) ^ aa) + X[8] + 0x00000002UL, 12);

    /* round 3 */
    HH(aa, bb, cc, dd, X[ 3], 11);
    HH(dd, aa, bb, cc, X[10], 13);
    HH(cc, dd, aa, bb, X[14],  6);
    HH(bb, cc, dd, aa, X[ 4],  7);
    HH(aa, bb, cc, dd, X[ 9], 14);
    HH(dd, aa, bb, cc, X[15],  9);
    HH(cc, dd, aa, bb, X[ 8], 13);
    HH(bb, cc, dd, aa, X[ 1], 15);
    HH(aa, bb, cc, dd, X[ 2], 14);
    HH(dd, aa, bb, cc, X[ 7],  8);
    HH(cc, dd, aa, bb, X[ 0], 13);
    //HH(bb, cc, dd, aa, X[ 6],  6);
    bb = ROLc(bb + ((cc | ~dd) ^ aa) + X[ 6] + 0x325b99a1UL,  6);
    HH(aa, bb, cc, dd, X[13],  5);
    //HH(dd, aa, bb, cc, X[11], 12);
    dd = ROLc(dd + ((aa | ~bb) ^ cc) + X[11] - 0x43234e06UL, 12);
    HH(cc, dd, aa, bb, X[ 5],  7);
    HH(bb, cc, dd, aa, X[12],  5);

    /* round 4 */
    II(aa, bb, cc, dd, X[ 1], 11);
    II(dd, aa, bb, cc, X[ 9], 12);
    //II(cc, dd, aa, bb, X[11], 14);
    cc = ROLc(cc + ((dd & bb) | (aa & ~bb)) + X[11] + 0x325b99a1UL, 14);
    II(bb, cc, dd, aa, X[10], 15);
    II(aa, bb, cc, dd, X[ 0], 14);
    //II(dd, aa, bb, cc, X[ 8], 15);
    dd = ROLc(dd + ((aa & cc) | (bb & ~cc)) + X[ 8] + 0xbcdcb1fbUL, 15);
    II(cc, dd, aa, bb, X[12],  9);
    II(bb, cc, dd, aa, X[ 4],  8);
    II(aa, bb, cc, dd, X[13],  9);
    //II(dd, aa, bb, cc, X[ 3], 14);
    dd = ROLc(dd + ((aa & cc) | (bb & ~cc)) + X[ 3] + 0x1baed69cUL, 14);
    II(cc, dd, aa, bb, X[ 7],  5);
    //II(bb, cc, dd, aa, X[15],  6);
    bb = ROLc(bb + ((cc & aa) | (dd & ~aa)) + X[15] + 0x00000002UL,  6);
    II(aa, bb, cc, dd, X[14],  8);
    II(dd, aa, bb, cc, X[ 5],  6);
    II(cc, dd, aa, bb, X[ 6],  5);
    //II(bb, cc, dd, aa, X[ 2], 12);
    bb = ROLc(bb + ((cc & aa) | (dd & ~aa)) + X[ 2] - 0x43234e04UL, 12);

    /* parallel round 1 */
    III(aaa, bbb, ccc, ddd, X[ 5],  8);
    III(ddd, aaa, bbb, ccc, X[14],  9);
    III(ccc, ddd, aaa, bbb, X[ 7],  9);
    III(bbb, ccc, ddd, aaa, X[ 0], 11);
    III(aaa, bbb, ccc, ddd, X[ 9], 13);
    III(ddd, aaa, bbb, ccc, X[ 2], 15);
    //III(ccc, ddd, aaa, bbb, X[11], 15);
    ccc = ROLc(ccc + ((ddd & bbb) | (aaa & ~bbb)) + X[11] + 0x325b99a1UL, 15);
    III(bbb, ccc, ddd, aaa, X[ 4],  5);
    III(aaa, bbb, ccc, ddd, X[13],  7);
    III(ddd, aaa, bbb, ccc, X[ 6],  7);
    //III(ccc, ddd, aaa, bbb, X[15],  8);
    ccc = ROLc(ccc + ((ddd & bbb) | (aaa & ~bbb)) + X[15] - 0x43234e07UL,  8);
    III(bbb, ccc, ddd, aaa, X[ 8], 11);
    III(aaa, bbb, ccc, ddd, X[ 1], 14);
    III(ddd, aaa, bbb, ccc, X[10], 14);
    //III(ccc, ddd, aaa, bbb, X[ 3], 12);
    ccc = ROLc(ccc + ((ddd & bbb) | (aaa & ~bbb)) + X[ 3] - 0x43234e04UL, 12);
    III(bbb, ccc, ddd, aaa, X[12],  6);

    /* parallel round 2 */
    HHH(aaa, bbb, ccc, ddd, X[ 6],  9);
    HHH(ddd, aaa, bbb, ccc, X[11], 13);
    HHH(ccc, ddd, aaa, bbb, X[ 3], 15);
    HHH(bbb, ccc, ddd, aaa, X[ 7],  7);
    HHH(aaa, bbb, ccc, ddd, X[ 0], 12);
    HHH(ddd, aaa, bbb, ccc, X[13],  8);
    //HHH(ccc, ddd, aaa, bbb, X[ 5],  9);
    ccc = ROLc(ccc + ((ddd | ~aaa) ^ bbb) + X[ 5] - 0x43234e07UL,  9);
    //HHH(bbb, ccc, ddd, aaa, X[10], 11);
    bbb = ROLc(bbb + ((ccc | ~ddd) ^ aaa) + X[10] - 0x43234e03UL, 11);
    HHH(aaa, bbb, ccc, ddd, X[14],  7);
    HHH(ddd, aaa, bbb, ccc, X[15],  7);
    HHH(ccc, ddd, aaa, bbb, X[ 8], 12);
    HHH(bbb, ccc, ddd, aaa, X[12],  7);
    HHH(aaa, bbb, ccc, ddd, X[ 4],  6);
    HHH(ddd, aaa, bbb, ccc, X[ 9], 15);
    //HHH(ccc, ddd, aaa, bbb, X[ 1], 13);
    ccc = ROLc(ccc + ((ddd | ~aaa) ^ bbb) + X[ 1] + 0x325b99a1UL, 13);
    HHH(bbb, ccc, ddd, aaa, X[ 2], 11);

    /* parallel round 3 */
    GGG(aaa, bbb, ccc, ddd, X[15],  9);
    GGG(ddd, aaa, bbb, ccc, X[ 5],  7);
    GGG(ccc, ddd, aaa, bbb, X[ 1], 15);
    GGG(bbb, ccc, ddd, aaa, X[ 3], 11);
    GGG(aaa, bbb, ccc, ddd, X[ 7],  8);
    GGG(ddd, aaa, bbb, ccc, X[14],  6);
    //GGG(ccc, ddd, aaa, bbb, X[ 6],  6);
    ccc = ROLc(ccc + ((ddd & aaa) | (~ddd & bbb)) + X[ 6] - 0x43234e02UL,  6);
    GGG(bbb, ccc, ddd, aaa, X[ 9], 14);
    GGG(aaa, bbb, ccc, ddd, X[11], 12);
    //GGG(ddd, aaa, bbb, ccc, X[ 8], 13);
    ddd = ROLc(ddd + ((aaa & bbb) | (~aaa & ccc)) + X[ 8] + 0x5a82798aUL, 13);
    GGG(ccc, ddd, aaa, bbb, X[12],  5);
    GGG(bbb, ccc, ddd, aaa, X[ 2], 14);
    GGG(aaa, bbb, ccc, ddd, X[10], 13);
    GGG(ddd, aaa, bbb, ccc, X[ 0], 13);
    //GGG(ccc, ddd, aaa, bbb, X[ 4],  7);
    ccc = ROLc(ccc + ((ddd & aaa) | (~ddd & bbb)) + X[ 4] + 0x41d42d5dUL,  7);
    GGG(bbb, ccc, ddd, aaa, X[13],  5);

    /* parallel round 4 */
    FFF(aaa, bbb, ccc, ddd, X[ 8], 15);
    //FFF(ddd, aaa, bbb, ccc, X[ 6],  5);
    ddd = ROLc(ddd + (aaa ^ bbb ^ ccc) + X[6] - 0x43234e02UL, 5);
    FFF(ccc, ddd, aaa, bbb, X[ 4],  8);
    FFF(bbb, ccc, ddd, aaa, X[ 1], 11);
    FFF(aaa, bbb, ccc, ddd, X[ 3], 14);
    FFF(ddd, aaa, bbb, ccc, X[11], 14);
    FFF(ccc, ddd, aaa, bbb, X[15],  6);
    FFF(bbb, ccc, ddd, aaa, X[ 0], 14);
    FFF(aaa, bbb, ccc, ddd, X[ 5],  6);
    FFF(ddd, aaa, bbb, ccc, X[12],  9);
    FFF(ccc, ddd, aaa, bbb, X[ 2], 12);
    FFF(bbb, ccc, ddd, aaa, X[13],  9);
    FFF(aaa, bbb, ccc, ddd, X[ 9], 12);
    FFF(ddd, aaa, bbb, ccc, X[ 7],  5);
    FFF(ccc, ddd, aaa, bbb, X[10], 15);
    FFF(bbb, ccc, ddd, aaa, X[14],  8);

    /* combine results */
    ddd += cc + md->state[1];               /* final result for MDbuf[0] */
    md->state[1] = md->state[2] + dd + aaa;
    md->state[2] = md->state[3] + aa + bbb + 1;
    md->state[3] = md->state[0] + bb + ccc;
    md->state[0] = ddd;
}

/**
   Initialize the hash state
   @param md   The hash state you wish to initialize
*/
static void ripemd128_init(ripemd128_state *md)
{
    assert(md != NULL);
    md->state[0] = 0x10257436UL;
    md->state[1] = 0xa8bd9cfeUL;
    md->state[2] = 0x9efcad8bUL;
    md->state[3] = 0x12375460UL;
    md->curlen   = 0;
    md->length   = 0;
}

/**
   Process a block of memory though the hash
   @param md     The hash state
   @param in     The data to hash
   @param inlen  The length of the data (octets)
*/
HASH_PROCESS(ripemd128_process, ripemd128_compress, ripemd128_state, 64)

/**
   Terminate the hash to get the digest
   @param md  The hash state
   @param out [out] The destination of the hash (16 bytes)
*/
static void ripemd128_done(ripemd128_state *md, unsigned char *out)
{
    int i;

    assert(md  != NULL);
    assert(out != NULL);
    assert(md->curlen < sizeof(md->buf));

    /* increase the length of the message */
    md->length += md->curlen * 8;

    /* append the '1' bit */
    md->buf[md->curlen++] = (unsigned char)0x80;

    /* if the length is currently above 56 bytes we append zeros
     * then compress.  Then we can fall back to padding zeros and length
     * encoding like normal.
     */
    if (md->curlen > 56) {
        while (md->curlen < 64) {
            md->buf[md->curlen++] = (unsigned char)0;
        }
        ripemd128_compress(md, md->buf);
        md->curlen = 0;
    }

    /* pad upto 56 bytes of zeroes */
    while (md->curlen < 56) {
        md->buf[md->curlen++] = (unsigned char)0;
    }

    /* store length */
    STORE64L(md->length, md->buf+56);
    ripemd128_compress(md, md->buf);

    /* copy output */
    for (i = 0; i < 4; i++) {
        STORE32L(md->state[i], out+(4*i));
    }
}


/** SECTION: libTomCrypt end **/


PYTHON_OBJECT(RuijieRipemd128, ripemd128)
