#include <stdlib.h>
#include <stdint.h>
#include <Python.h>
#include <pystrhex.h>


/** SECTION: libTomCrypt start **/
/* the MD5 implementation is modified from libTomCrypt
 * http://www.libtom.net/LibTomCrypt/ */

/* rotate the hard way (platform optimizations could be done) */
#define ROLc(x, y) ( (((unsigned long)(x)<<(unsigned long)((y)&31)) | (((unsigned long)(x)&0xFFFFFFFFUL)>>(unsigned long)(32-((y)&31)))) & 0xFFFFFFFFUL)


/* Endian Neutral macros that work on all platforms */
#define STORE32L(x, y)                                                                     \
     { (y)[3] = (unsigned char)(((x)>>24)&255); (y)[2] = (unsigned char)(((x)>>16)&255);   \
       (y)[1] = (unsigned char)(((x)>>8)&255); (y)[0] = (unsigned char)((x)&255); }

#define LOAD32L(x, y)                            \
     { x = ((unsigned long)((y)[3] & 255)<<24) | \
           ((unsigned long)((y)[2] & 255)<<16) | \
           ((unsigned long)((y)[1] & 255)<<8)  | \
           ((unsigned long)((y)[0] & 255)); }

#define STORE64L(x, y)                                                                     \
     { (y)[7] = (unsigned char)(((x)>>56)&255); (y)[6] = (unsigned char)(((x)>>48)&255);   \
       (y)[5] = (unsigned char)(((x)>>40)&255); (y)[4] = (unsigned char)(((x)>>32)&255);   \
       (y)[3] = (unsigned char)(((x)>>24)&255); (y)[2] = (unsigned char)(((x)>>16)&255);   \
       (y)[1] = (unsigned char)(((x)>>8)&255); (y)[0] = (unsigned char)((x)&255); }


#define MD5_BLOCKSIZE  64
#define MD5_DIGESTSIZE 16


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


static void md5_compress(md5_state *md5, unsigned char *buf)
{
    uint32_t i, W[16], a, b, c, d;

    /* copy the state into 512-bits into W[0..15] */
    for (i = 0; i < 16; i++)
        LOAD32L(W[i], buf + (4*i));

    /* copy state */
    a = md5->state[0];
    b = md5->state[1];
    c = md5->state[2];
    d = md5->state[3];

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

    md5->state[0] = md5->state[0] + a;
    md5->state[1] = md5->state[1] + b;
    md5->state[2] = md5->state[2] + c;
    md5->state[3] = md5->state[3] + d;
}

/**
   Initialize the hash state
   @param md5  The hash state you wish to initialize
*/
void md5_init(md5_state *md5)
{
   assert(md5 != NULL);
   md5->state[0] = 0x50137246UL;  // 0x67452301UL;
   md5->state[1] = 0x8acf9dbeUL;  // 0xefcdab89UL;
   md5->state[2] = 0xc9efacedUL;  // 0x98badcfeUL;
   md5->state[3] = 0x25647013UL;  // 0x10325476UL;
   md5->curlen = 0;
   md5->length = 0;
}

/**
   Process a block of memory though the hash
   @param md5    The hash state
   @param in     The data to hash
   @param inlen  The length of the data (octets)
*/
void md5_process(md5_state *md5, const unsigned char *in, unsigned long inlen)
{
    unsigned long n;

    assert(md5 != NULL);
    assert(in  != NULL);
    assert(md5->curlen <= sizeof(md5->buf));

    while(inlen > 0)
    {
        if (md5->curlen == 0 && inlen >= MD5_BLOCKSIZE)
        {
            md5_compress(md5, (unsigned char *)in);
            md5->length += MD5_BLOCKSIZE * 8;
            in          += MD5_BLOCKSIZE;
            inlen       -= MD5_BLOCKSIZE;
        }
        else
        {
            n = Py_MIN(inlen, (Py_ssize_t)(MD5_BLOCKSIZE - md5->curlen));
            memcpy(md5->buf + md5->curlen, in, (size_t)n);
            md5->curlen += n;
            in          += n;
            inlen       -= n;
            if (md5->curlen == MD5_BLOCKSIZE)
            {
                md5_compress(md5, md5->buf);
                md5->length += 8 * MD5_BLOCKSIZE;
                md5->curlen  = 0;
            }
        }
    }
}


/**
   Terminate the hash to get the digest
   @param md5  The hash state
   @param out [out] The destination of the hash (16 bytes)
   @return CRYPT_OK if successful
*/
void md5_done(md5_state *md5, unsigned char *out)
{
    int i;

    assert(md5 != NULL);
    assert(out != NULL);
    assert(md5->curlen < sizeof(md5->buf));

    /* increase the length of the message */
    md5->length += md5->curlen * 8;

    /* append the '1' bit */
    md5->buf[md5->curlen++] = (unsigned char)0x80;

    /* if the length is currently above 56 bytes we append zeros
     * then compress.  Then we can fall back to padding zeros and length
     * encoding like normal.
     */
    if (md5->curlen > 56)
    {
        while (md5->curlen < 64)
            md5->buf[md5->curlen++] = (unsigned char)0;
        md5_compress(md5, md5->buf);
        md5->curlen = 0;
    }

    /* pad upto 56 bytes of zeroes */
    while (md5->curlen < 56)
        md5->buf[md5->curlen++] = (unsigned char)0;

    /* store length */
    STORE64L(md5->length, md5->buf+56);
    md5_compress(md5, md5->buf);

    /* copy output */
    for (i = 0; i < 4; i++)
        STORE32L(md5->state[i], out+(4*i));
}

/** SECTION: libTomCrypt end **/
/** SECTION: Python Class start **/
/* C API learned from CPython md5module.c and documents
 * https://github.com/python/cpython/blob/master/Modules/md5module.c
 * https://docs.python.org/3/extending/extending.html
 * https://docs.python.org/3/extending/newtypes.html */

/*
 * Given a PyObject* obj, fill in the Py_buffer* viewp with the result
 * of PyObject_GetBuffer.  Sets an exception and issues the erraction
 * on any errors, e.g. 'return NULL' or 'goto error'.
 */
#define GET_BUFFER_VIEW_OR_ERROR(obj, viewp, erraction) do { \
        if (PyUnicode_Check((obj))) { \
            PyErr_SetString(PyExc_TypeError, \
                            "Unicode-objects must be encoded before hashing");\
            erraction; \
        } \
        if (!PyObject_CheckBuffer((obj))) { \
            PyErr_SetString(PyExc_TypeError, \
                            "object supporting the buffer API required"); \
            erraction; \
        } \
        if (PyObject_GetBuffer((obj), (viewp), PyBUF_SIMPLE) == -1) { \
            erraction; \
        } \
        if ((viewp)->ndim > 1) { \
            PyErr_SetString(PyExc_BufferError, \
                            "Buffer must be single dimension"); \
            PyBuffer_Release((viewp)); \
            erraction; \
        } \
    } while(0)

#define GET_BUFFER_VIEW_OR_ERROUT(obj, viewp) \
GET_BUFFER_VIEW_OR_ERROR(obj, viewp, return NULL)


static PyTypeObject ruijie_md5_type;


typedef struct {
    PyObject_HEAD
    /* Type-specific fields go here. */
    md5_state md5;
} RuijieMD5;


static PyObject *ruijie_md5_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    return type->tp_alloc(type, 0);
}


static int ruijie_md5_init(RuijieMD5 *self, PyObject *args, PyObject *kwds)
{
    Py_buffer buffer = {0};

    PyArg_ParseTuple(args, "|y*", &buffer);

    md5_init(&self->md5);
    if(buffer.buf)
    {
        md5_process(&self->md5, buffer.buf, buffer.len);
        PyBuffer_Release(&buffer);
    }

    return 0;
}


static void ruijie_md5_del(PyObject *self)
{
    Py_TYPE(self)->tp_free(self);
}


static PyObject *ruijie_md5_digestsize(PyObject *self, void *closure)
{
    return PyLong_FromLong(MD5_DIGESTSIZE);
}


static PyObject *ruijie_md5_blocksize(PyObject *self, void *closure)
{
    return PyLong_FromLong(MD5_BLOCKSIZE);
}


static PyObject *ruijie_md5_name(PyObject *self, void *closure)
{
    return PyUnicode_FromString("ruijie_md5");
}


static PyObject *ruijie_md5_update(RuijieMD5 *self, PyObject *object)
{
    Py_buffer buffer;

    GET_BUFFER_VIEW_OR_ERROUT(object, &buffer);
    md5_process(&self->md5, buffer.buf, buffer.len);
    PyBuffer_Release(&buffer);

    Py_RETURN_NONE;
}


static PyObject *ruijie_md5_digest(RuijieMD5 *self)
{
    unsigned char digest[MD5_DIGESTSIZE];
    md5_state     temp;

    temp = self->md5;
    md5_done(&temp, digest);
    return PyBytes_FromStringAndSize((const char *)digest, MD5_DIGESTSIZE);
}


static PyObject *ruijie_md5_hexdigest(RuijieMD5 *self)
{
    unsigned char digest[MD5_DIGESTSIZE];
    md5_state     temp;

    /* Get the raw (binary) digest value */
    temp = self->md5;
    md5_done(&temp, digest);

    return _Py_strhex((const char*)digest, MD5_DIGESTSIZE);
}


static PyObject *ruijie_md5_copy(RuijieMD5 *self)
{
    RuijieMD5 *copy = (RuijieMD5 *)Py_TYPE(self)->tp_alloc(Py_TYPE(self), 0);
    if (copy == NULL) return NULL;

    copy->md5 = self->md5;
    return (PyObject *)copy;
}


static PyGetSetDef ruijie_md5_getseters[] = {
    {"digest_size", (getter)ruijie_md5_digestsize, NULL, NULL, NULL},
    {"block_size" , (getter)ruijie_md5_blocksize , NULL, NULL, NULL},
    {"name"       , (getter)ruijie_md5_name      , NULL, NULL, NULL},
    {NULL}  /* Sentinel */
};

static PyMethodDef ruijei_md5_methods[] = {
    {"update",    (PyCFunction)ruijie_md5_update,    METH_O,      NULL},
    {"digest",    (PyCFunction)ruijie_md5_digest,    METH_NOARGS, NULL},
    {"hexdigest", (PyCFunction)ruijie_md5_hexdigest, METH_NOARGS, NULL},
    {"copy",      (PyCFunction)ruijie_md5_copy,      METH_NOARGS, NULL},
    {NULL}         /* sentinel */
};

static PyTypeObject ruijie_md5_type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name      = "extra.RuijieMD5",
    .tp_basicsize = sizeof(RuijieMD5),
    .tp_dealloc   = ruijie_md5_del,
    .tp_flags     = Py_TPFLAGS_DEFAULT,
    .tp_methods   = ruijei_md5_methods,
    .tp_getset    = ruijie_md5_getseters,
    .tp_init      = (initproc)ruijie_md5_init,
    .tp_new       = ruijie_md5_new
};


PyObject *ruijie_md5_register(PyObject *module)
{
    if (PyType_Ready(&ruijie_md5_type) < 0)
        return NULL;

    Py_INCREF(&ruijie_md5_type);
    PyModule_AddObject(module, "RuijieMD5", (PyObject *)&ruijie_md5_type);

    return module;
}

/** SECTION: Python Class end **/
