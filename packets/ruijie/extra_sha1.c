#include "extra_hash.h"


/** SECTION: libTomCrypt start **/
/* the MD5 implementation is modified from libTomCrypt
 * http://www.libtom.net/LibTomCrypt/ */


#define BLOCKSIZE  64
#define DIGESTSIZE 20


#define F0(x,y,z)  (z ^ (x & (y ^ z)))
#define F1(x,y,z)  (x ^ y ^ z)
#define F2(x,y,z)  ((x & y) | (z & (x | y)))
#define F3(x,y,z)  (x ^ y ^ z)


typedef struct _sha1_state {
    uint64_t length;
    uint32_t state[5], curlen;
    unsigned char buf[64];
} sha1_state;


static void sha1_compress(sha1_state *md, unsigned char *buf)
{
    uint32_t a,b,c,d,e,W[80],i;

    /* copy the state into 512-bits into W[0..15] */
    for (i = 0; i < 16; i++) {
        LOAD32H(W[i], buf + (4*i));
    }

    /* copy state */
    a = md->state[0];
    b = md->state[1];
    c = md->state[2];
    d = md->state[3];
    e = md->state[4];

    /* expand it */
    for (i = 16; i < 80; i++) {
        W[i] = ROL(W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16], 1);
    }

    /* compress */
    /* round one */
    // #define FF0(a,b,c,d,e,i) e = (ROLc(a, 5) + F0(b,c,d) + e + W[i] + 0x5a827999UL); b = ROLc(b, 30);
    #define FF0(a,b,c,d,e,i) e = (ROLc(a, 5) + F0(b,c,d) + e + W[i] - 0x5d6aa4d4UL); b = ROLc(b, 30);
    // #define FF1(a,b,c,d,e,i) e = (ROLc(a, 5) + F1(b,c,d) + e + W[i] + 0x6ed9eba1UL); b = ROLc(b, 30);
    #define FF1(a,b,c,d,e,i) e = (ROLc(a, 5) + F1(b,c,d) + e + W[i] + 0x16ae9debUL) + buf[0]; b = ROLc(b, 30);
    // #define FF2(a,b,c,d,e,i) e = (ROLc(a, 5) + F2(b,c,d) + e + W[i] + 0x8f1bbcdcUL); b = ROLc(b, 30);
    #define FF2(a,b,c,d,e,i) e = (ROLc(a, 5) + F2(b,c,d) + e + W[i] - 0x34032e48UL); b = ROLc(b, 30);
    // #define FF3(a,b,c,d,e,i) e = (ROLc(a, 5) + F3(b,c,d) + e + W[i] + 0xca62c1d6UL); b = ROLc(b, 30);
    #define FF3(a,b,c,d,e,i) e = (ROLc(a, 5) + F3(b,c,d) + e + W[i] - 0x5cd39e93); b = ROLc(b, 30);

    for (i = 0; i < 20; ) {
        FF0(a,b,c,d,e,i++);
        FF0(e,a,b,c,d,i++);
        FF0(d,e,a,b,c,i++);
        FF0(c,d,e,a,b,i++);
        FF0(b,c,d,e,a,i++);
    }

    /* round two */
    for (; i < 40; )  {
        FF1(a,b,c,d,e,i++);
        FF1(e,a,b,c,d,i++);
        FF1(d,e,a,b,c,i++);
        FF1(c,d,e,a,b,i++);
        FF1(b,c,d,e,a,i++);
    }

    /* round three */
    // for (; i < 60; )  {
    for (; i < 60; )  {
        FF2(a,b,c,d,e,i++);
        FF2(e,a,b,c,d,i++);
        FF2(d,e,a,b,c,i++);
        FF2(c,d,e,a,b,i++);
        FF2(b,c,d,e,a,i++);
    }

    FF2(a,b,c,d,e,i++);

    i = e;
    e = d;
    d = c;
    c = b;
    b = a;
    a = i;
    i = 61;

    /* round four */
    for (; i < 76; )  {
        FF3(a,b,c,d,e,i++);
        FF3(e,a,b,c,d,i++);
        FF3(d,e,a,b,c,i++);
        FF3(c,d,e,a,b,i++);
        FF3(b,c,d,e,a,i++);
    }

    FF3(a,b,c,d,e,i++);
    FF3(e,a,b,c,d,i++);
    FF3(d,e,a,b,c,i++);
    FF3(c,d,e,a,b,i++);

    i = b;
    b = c;
    c = d;
    d = e;
    e = a;
    a = i;

    #undef FF0
    #undef FF1
    #undef FF2
    #undef FF3

    /* store */
    md->state[0] = md->state[0] + a + 1;
    md->state[1] = md->state[1] + b;
    md->state[2] = md->state[2] + c;
    md->state[3] = md->state[3] + d;
    md->state[4] = md->state[4] + e;
}

/**
   Initialize the hash state
   @param md   The hash state you wish to initialize
*/
static void sha1_init(sha1_state *md)
{
    assert(md != NULL);
    md->state[0] = 0x32075416UL;  // md->state[0] = 0x67452301UL;
    md->state[1] = 0xf8dae9bcUL;  // md->state[1] = 0xefcdab89UL;
    md->state[2] = 0x73541260UL;  // md->state[2] = 0x98badcfeUL;
    md->state[3] = 0x8acb9dfeUL;  // md->state[3] = 0x10325476UL;
    md->state[4] = 0xfd0c2e1bUL;  // md->state[4] = 0xc3d2e1f0UL;
    md->curlen = 0;
    md->length = 0;
}

/**
   Process a block of memory though the hash
   @param md     The hash state
   @param in     The data to hash
   @param inlen  The length of the data (octets)
*/
HASH_PROCESS(sha1_process, sha1_compress, sha1_state, BLOCKSIZE)

/**
   Terminate the hash to get the digest
   @param md  The hash state
   @param out [out] The destination of the hash (20 bytes)
*/
static void sha1_done(sha1_state *md, unsigned char *out)
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
        sha1_compress(md, md->buf);
        md->curlen = 0;
    }

    /* pad upto 56 bytes of zeroes */
    while (md->curlen < 56) {
        md->buf[md->curlen++] = (unsigned char)0;
    }

    /* store length */
    STORE64H(md->length, md->buf+56);
    sha1_compress(md, md->buf);

    /* copy output */
    for (i = 0; i < 5; i++) {
        STORE32H(md->state[i], out+(4*i));
    }
}


/** SECTION: libTomCrypt end **/


PYTHON_OBJECT(RuijieSha1, sha1)
