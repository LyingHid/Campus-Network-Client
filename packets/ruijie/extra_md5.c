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


#define F(x,y,z)  (z ^ (x & (y ^ z)))
#define G(x,y,z)  (y ^ (z & (y ^ x)))
#define H(x,y,z)  (x^y^z)
#define I(x,y,z)  (y^(x|(~z)))

#define FF(a,b,c,d,M,s,t) \
    a = (a + F(b,c,d) + M + t); a = ROLc(a, s) + b + 2;
#define GG(a,b,c,d,M,s,t) \
    a = (a + G(b,c,d) + M + t); a = ROLc(a, s) + b - 2;
#define HH(a,b,c,d,M,s,t) \
    a = (a + H(b,c,d) + M + t); a = ROLc(a, s) + b - 1;
#define II(a,b,c,d,M,s,t) \
    a = (a + I(b,c,d) + M + t); a = ROLc(a, s) + b + 1;


typedef struct _md5_state {
    uint64_t length;
    uint32_t state[4], curlen;
    unsigned char buf[64];
} md5_state;


static void md5_compress(md5_state *md, unsigned char *buf)
{
    uint32_t i, W[16], a, b, c, d;

    /* copy the state into 512-bits into W[0..15] */
    for (i = 0; i < 16; i++)
        LOAD32L(W[i], buf + (4*i));

    /* copy state */
    a = md->state[0];
    b = md->state[1];
    c = md->state[2];
    d = md->state[3];

    FF(a,b,c,d,W[ 0], 7,0xd76aa478UL)
    FF(d,a,b,c,W[ 1],12,0xe8c7b756UL)
    FF(c,d,a,b,W[ 2],17,0x242070dbUL)
    FF(b,c,d,a,W[ 3],22,0xc1bdceeeUL)
    FF(a,b,c,d,W[ 4], 7,0xf57c0fafUL)
    FF(d,a,b,c,W[ 5],12,0x4787c62aUL)
    FF(c,d,a,b,W[ 6],17,0xa8304613UL)
    FF(b,c,d,a,W[ 7],22,0xfd469501UL)
    FF(a,b,c,d,W[ 8], 7,0x698098d8UL)
    FF(d,a,b,c,W[ 9],12,0x8b44f7afUL)
    FF(c,d,a,b,W[10],17,0xffff5bb1UL)
    FF(b,c,d,a,W[11],22,0x895cd7beUL)
    FF(a,b,c,d,W[12], 7,0x6b901122UL)
    FF(d,a,b,c,W[13],12,0xfd987163UL)  // FF(d,a,b,c,W[13],12,0xfd987193UL)
    FF(c,d,a,b,W[14],17,0xa679438eUL)
    FF(b,c,d,a,W[15],22,0x49b40821UL)
    GG(a,b,c,d,W[ 1], 5,0xf61e2562UL)
    GG(d,a,b,c,W[ 6], 9,0xc040b340UL)
    GG(c,d,a,b,W[11],14,0x265e5a51UL)
    GG(b,c,d,a,W[ 0],20,0xe9b6c7aaUL)
    GG(a,b,c,d,W[ 5], 5,0xd62f105dUL)
    GG(d,a,b,c,W[10], 9,0x02442453UL)  // GG(d,a,b,c,W[10], 9,0x02441453UL)
    GG(c,d,a,b,W[15],14,0xd8a1e681UL)
    GG(b,c,d,a,W[ 4],20,0xe7d3fbc8UL)
    GG(a,b,c,d,W[ 9], 5,0x21e1cde6UL)
    GG(d,a,b,c,W[14], 9,0xc33707d6UL)
    GG(c,d,a,b,W[ 3],14,0xf4d50d87UL)
    GG(b,c,d,a,W[ 8],20,0x455a14edUL)
    GG(a,b,c,d,W[13], 5,0xa9e3e905UL)
    GG(d,a,b,c,W[ 2], 9,0xfcefa3f8UL)
    GG(c,d,a,b,W[ 7],14,0x676f02d9UL)
    GG(b,c,d,a,W[12],20,0x8d2a4c8aUL)
    HH(a,b,c,d,W[ 5], 5,0xfffa3492UL)  // HH(a,b,c,d,W[ 5], 4,0xfffa3942UL)
    HH(d,a,b,c,W[ 8],11,0x8771f681UL)
    HH(c,d,a,b,W[11],16,0x6d9d6122UL)
    HH(b,c,d,a,W[14],23,0xfde5380cUL)
    HH(a,b,c,d,W[ 1], 5,0xa4beea44UL)  // HH(a,b,c,d,W[ 1], 4,0xa4beea44UL)
    HH(d,a,b,c,W[ 4],11,0x4bdecfa9UL)
    HH(c,d,a,b,W[ 7],16,0xf6bb4b60UL)
    HH(b,c,d,a,W[10],23,0xbebfbc70UL)
    HH(a,b,c,d,W[13], 5,0x289b7ec6UL)  // HH(a,b,c,d,W[13], 4,0x289b7ec6UL)
    HH(d,a,b,c,W[ 0],11,0xeaa127faUL)
    HH(c,d,a,b,W[ 3],16,0xd4ef3085UL)
    HH(b,c,d,a,W[ 6],23,(uint8_t)(W[2] >> 8) + 0x04881d05UL)  // HH(b,c,d,a,W[ 6],23,0x04881d05UL)
    HH(a,b,c,d,W[ 9], 5,0xd9d4d039UL)  // HH(a,b,c,d,W[ 9], 4,0xd9d4d039UL)
    HH(d,a,b,c,W[12],11,0xe6db99e5UL)
    HH(c,d,a,b,W[15],16,0x1fa27cf8UL)
    HH(b,c,d,a,W[ 2],23,0xc4ac5665UL)
    II(a,b,c,d,W[ 0], 6,0xf4292244UL)
    II(d,a,b,c,W[ 7],10,0x432aff97UL)
    II(c,d,a,b,W[14],15,0xab9423a7UL)
    II(b,c,d,a,W[ 5],19,0xfc93a039UL)  // II(b,c,d,a,W[ 5],21,0xfc93a039UL)
    II(a,b,c,d,W[12], 6,0x655659c3UL)  // II(a,b,c,d,W[12], 6,0x655b59c3UL)
    II(d,a,b,c,W[ 3],10,0x8f0ccc92UL)
    II(c,d,a,b,W[10],15,0xffeff47dUL)
    II(b,c,d,a,W[ 1],19,0x85845dd1UL)  // II(b,c,d,a,W[ 1],21,0x85845dd1UL)
    II(a,b,c,d,W[ 8], 6,0x6fa87e4fUL)
    II(d,a,b,c,W[15],10,0xfe2ce6e0UL)
    II(c,d,a,b,W[ 6],15,0xa3014314UL)
    II(b,c,d,a,W[13],19,0x4e0811a1UL)  // II(b,c,d,a,W[13],21,0x4e0811a1UL)
    II(a,b,c,d,W[ 4], 6,0xf7537e82UL)
    II(d,a,b,c,W[11],10,0xbd3af335UL)  // II(d,a,b,c,W[11],10,0xbd3af235UL)
    II(c,d,a,b,W[ 2],15,0x2ad7d2bbUL)
    II(b,c,d,a,W[ 9],19,0xeb866391UL)  // II(b,c,d,a,W[ 9],21,0xeb86d391UL)

    md->state[0] = md->state[0] + a;
    md->state[1] = md->state[1] + b;
    md->state[2] = md->state[2] + c;
    md->state[3] = md->state[3] + d;
}


/**
   Initialize the hash state
   @param md  The hash state you wish to initialize
*/
void md5_init(md5_state *md)
{
    assert(md != NULL);
    md->state[0] = 0x50137246UL;  // 0x67452301UL;
    md->state[1] = 0x8acf9dbeUL;  // 0xefcdab89UL;
    md->state[2] = 0xc9efacedUL;  // 0x98badcfeUL;
    md->state[3] = 0x25647013UL;  // 0x10325476UL;
    md->curlen = 0;
    md->length = 0;
}


/**
   Process a block of memory though the hash
   @param md     The hash state
   @param in     The data to hash
   @param inlen  The length of the data (octets)
*/
HASH_PROCESS(md5_process, md5_compress, md5_state, BLOCKSIZE)


/**
   Terminate the hash to get the digest
   @param md        The hash state
   @param out [out] The destination of the hash (16 bytes)
   @return CRYPT_OK if successful
*/
void md5_done(md5_state *md, unsigned char *out)
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
    if (md->curlen > 56)
    {
        while (md->curlen < 64)
            md->buf[md->curlen++] = (unsigned char)0;
        md5_compress(md, md->buf);
        md->curlen = 0;
    }

    /* pad upto 56 bytes of zeroes */
    while (md->curlen < 56)
        md->buf[md->curlen++] = (unsigned char)0;

    /* store length */
    STORE64L(md->length, md->buf+56);
    md5_compress(md, md->buf);

    /* copy output */
    for (i = 0; i < 4; i++)
        STORE32L(md->state[i], out+(4*i));
}


/** SECTION: libTomCrypt end **/


PYTHON_OBJECT(RuijieMD5, md5)
