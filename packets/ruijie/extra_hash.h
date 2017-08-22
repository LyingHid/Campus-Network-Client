#ifndef HEADER_EXTRA_HASH
#define HEADER_EXTRA_HASH


#include <stdint.h>
#include <Python.h>
#include <pystrhex.h>


#define min(x, y) ({                  \
    typeof(x) _min1 = (x);            \
    typeof(x) _min2 = (y);            \
    (void) (&_min1 == &_min2);        \
    _min1 < _min2 ? _min1 : _min2; })


/** SECTION: libTomCrypt start **/
/* the MD5 implementation is modified from libTomCrypt
 * http://www.libtom.net/LibTomCrypt/ */


/* uint64_t: 64-bit data type */
#define CONST64(n) n ## ULL


#define byte(x, n) (((x) >> (8 * (n))) & 255)


/* rotate the hard way (platform optimizations could be done) */
#define ROL(x, y) ( (((uint32_t)(x)<<(uint32_t)((y)&31)) | (((uint32_t)(x)&0xFFFFFFFFUL)>>(uint32_t)((32-((y)&31))&31))) & 0xFFFFFFFFUL)
#define ROLc(x, y) ( (((uint32_t)(x)<<(uint32_t)((y)&31)) | (((uint32_t)(x)&0xFFFFFFFFUL)>>(uint32_t)(32-((y)&31)))) & 0xFFFFFFFFUL)


/* Endian Neutral macros that work on all platforms */
#define LOAD32L(x, y)                       \
     { x = ((uint32_t)((y)[3] & 255)<<24) | \
           ((uint32_t)((y)[2] & 255)<<16) | \
           ((uint32_t)((y)[1] & 255)<<8)  | \
           ((uint32_t)((y)[0] & 255)); }

#define LOAD32H(x, y)                      \
    { x = ((uint32_t)((y)[0] & 255)<<24) | \
          ((uint32_t)((y)[1] & 255)<<16) | \
          ((uint32_t)((y)[2] & 255)<<8)  | \
          ((uint32_t)((y)[3] & 255)); }

#define STORE32L(x, y)                                                                  \
  { (y)[3] = (unsigned char)(((x)>>24)&255); (y)[2] = (unsigned char)(((x)>>16)&255);   \
    (y)[1] = (unsigned char)(((x)>>8)&255); (y)[0] = (unsigned char)((x)&255); }

#define STORE32H(x, y)                                                                    \
    { (y)[0] = (unsigned char)(((x)>>24)&255); (y)[1] = (unsigned char)(((x)>>16)&255);   \
      (y)[2] = (unsigned char)(((x)>>8)&255); (y)[3] = (unsigned char)((x)&255); } while(0)

#define LOAD64L(x, y)                                                        \
    { x = (((uint64_t)((y)[7] & 255))<<56)|(((uint64_t)((y)[6] & 255))<<48)| \
          (((uint64_t)((y)[5] & 255))<<40)|(((uint64_t)((y)[4] & 255))<<32)| \
          (((uint64_t)((y)[3] & 255))<<24)|(((uint64_t)((y)[2] & 255))<<16)| \
          (((uint64_t)((y)[1] & 255))<<8)|(((uint64_t)((y)[0] & 255))); }

#define LOAD64H(x, y)                                                         \
    { x = (((uint64_t)((y)[0] & 255))<<56)|(((uint64_t)((y)[1] & 255))<<48) | \
          (((uint64_t)((y)[2] & 255))<<40)|(((uint64_t)((y)[3] & 255))<<32) | \
          (((uint64_t)((y)[4] & 255))<<24)|(((uint64_t)((y)[5] & 255))<<16) | \
          (((uint64_t)((y)[6] & 255))<<8)|(((uint64_t)((y)[7] & 255))); }

#define STORE64L(x, y)                                                                     \
     { (y)[7] = (unsigned char)(((x)>>56)&255); (y)[6] = (unsigned char)(((x)>>48)&255);   \
       (y)[5] = (unsigned char)(((x)>>40)&255); (y)[4] = (unsigned char)(((x)>>32)&255);   \
       (y)[3] = (unsigned char)(((x)>>24)&255); (y)[2] = (unsigned char)(((x)>>16)&255);   \
       (y)[1] = (unsigned char)(((x)>>8)&255); (y)[0] = (unsigned char)((x)&255); }

#define STORE64H(x, y)                                                                     \
    { (y)[0] = (unsigned char)(((x)>>56)&255); (y)[1] = (unsigned char)(((x)>>48)&255);    \
      (y)[2] = (unsigned char)(((x)>>40)&255); (y)[3] = (unsigned char)(((x)>>32)&255);    \
      (y)[4] = (unsigned char)(((x)>>24)&255); (y)[5] = (unsigned char)(((x)>>16)&255);    \
      (y)[6] = (unsigned char)(((x)>>8)&255); (y)[7] = (unsigned char)((x)&255); }


/* a simple macro for making hash "process" functions */
#define HASH_PROCESS(func_name, compress_name, state_name, block_size) \
static void func_name(state_name *md, const unsigned char *in, unsigned long inlen) \
{ \
    unsigned long n; \
\
    assert(md != NULL); \
    assert(in != NULL); \
    assert(md->curlen <= sizeof(md->buf)); \
 \
    while (inlen > 0) \
    { \
        if (md->curlen == 0 && inlen >= block_size) \
        { \
            compress_name(md, (unsigned char *)in); \
            md->length += block_size * 8; \
            in         += block_size; \
            inlen      -= block_size; \
        } \
        else \
        { \
            n = min(inlen, (block_size - md->curlen)); \
            memcpy(md->buf + md->curlen, in, (size_t)n); \
            md->curlen += n; \
            in         += n; \
            inlen      -= n; \
            if (md->curlen == block_size) \
            { \
                compress_name(md, md->buf); \
                md->length += 8 * block_size; \
                md->curlen  = 0; \
            } \
        } \
    } \
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


#define OBJECT_DEF(tom) \
    typedef struct { \
        PyObject_HEAD \
        /* Type-specific fields go here. */ \
        tom ## _state hash_state; \
    } HashObject; \

#define OBJECT_INIT(tom) \
    static int hash_init(HashObject *self, PyObject *args, PyObject *kwds) \
    { \
        Py_buffer buffer = {0}; \
 \
        PyArg_ParseTuple(args, "|y*", &buffer); \
 \
        tom ## _init(&self->hash_state); \
        if(buffer.buf) \
        { \
            tom ## _process(&self->hash_state, buffer.buf, buffer.len); \
            PyBuffer_Release(&buffer); \
        } \
 \
        return 0; \
    }

#define OBJECT_DEL() \
    static void hash_del(PyObject *self) \
    { \
        Py_TYPE(self)->tp_free(self); \
    }

#define OBJECT_DIGESTSIZE() \
    static PyObject *hash_digestsize(PyObject *self, void *closure) \
    { \
        return PyLong_FromLong(DIGESTSIZE); \
    }

#define OBJECT_BLOCKSIZE() \
    static PyObject *hash_blocksize(PyObject *self, void *closure) \
    { \
        return PyLong_FromLong(BLOCKSIZE); \
    } \

#define OBJECT_NAME(tom) \
    static PyObject *hash_name(PyObject *self, void *closure) \
    { \
        return PyUnicode_FromString("ruijie_" #tom); \
    }

#define OBJECT_UPDATE(tom) \
    static PyObject *hash_update(HashObject *self, PyObject *object) \
    { \
        Py_buffer buffer; \
 \
        GET_BUFFER_VIEW_OR_ERROUT(object, &buffer); \
        tom ## _process(&self->hash_state, buffer.buf, buffer.len); \
        PyBuffer_Release(&buffer); \
 \
        Py_RETURN_NONE; \
    }

#define OBJECT_DIGEST(tom) \
    static PyObject *hash_digest(HashObject *self) \
    { \
        unsigned char digest[DIGESTSIZE]; \
        tom ## _state temp; \
 \
        temp = self->hash_state; \
        tom ## _done(&temp, digest); \
        return PyBytes_FromStringAndSize((const char *)digest, DIGESTSIZE); \
    }

#define OBJECT_HEXDIGEST(tom) \
    static PyObject *hash_hexdigest(HashObject *self) \
    { \
        unsigned char digest[DIGESTSIZE]; \
        tom ## _state temp; \
 \
        /* Get the raw (binary) digest value */ \
        temp = self->hash_state; \
        tom ## _done(&temp, digest); \
 \
        return _Py_strhex((const char*)digest, DIGESTSIZE); \
    }

#define OBJECT_COPY() \
    static PyObject *hash_copy(HashObject *self) \
    { \
        HashObject *copy = (HashObject *)Py_TYPE(self)->tp_alloc(Py_TYPE(self), 0); \
        if (copy == NULL) return NULL; \
 \
        copy->hash_state = self->hash_state; \
        return (PyObject *)copy; \
    }

#define OBJECT_GETSETER_DEF()                                       \
    static PyGetSetDef hash_getseters[] = {                         \
        {"digest_size", (getter)hash_digestsize, NULL, NULL, NULL}, \
        {"block_size" , (getter)hash_blocksize , NULL, NULL, NULL}, \
        {"name"       , (getter)hash_name      , NULL, NULL, NULL}, \
        {NULL}  /* Sentinel */                                      \
    };

#define OBJECT_METHODS_DEF()                                           \
    static PyMethodDef hash_methods[] = {                              \
        {"update",    (PyCFunction)hash_update,    METH_O,      NULL}, \
        {"digest",    (PyCFunction)hash_digest,    METH_NOARGS, NULL}, \
        {"hexdigest", (PyCFunction)hash_hexdigest, METH_NOARGS, NULL}, \
        {"copy",      (PyCFunction)hash_copy,      METH_NOARGS, NULL}, \
        {NULL}         /* sentinel */                                  \
    };

#define OBJECT_TYPE(name)                    \
    static PyTypeObject type_object = {      \
        PyVarObject_HEAD_INIT(NULL, 0)       \
        .tp_name      = "extra." #name,      \
        .tp_basicsize = sizeof(HashObject),  \
        .tp_dealloc   = hash_del,            \
        .tp_flags     = Py_TPFLAGS_DEFAULT,  \
        .tp_methods   = hash_methods,        \
        .tp_getset    = hash_getseters,      \
        .tp_init      = (initproc)hash_init, \
    };

#define OBJECT_REGISTER(name, tom) \
    PyObject *ruijie_ ## tom ## _register(PyObject *module) \
    { \
        type_object.tp_new = PyType_GenericNew; \
        if (PyType_Ready(&type_object) < 0) \
            return NULL; \
 \
        Py_INCREF(&type_object); \
        PyModule_AddObject(module, #name, (PyObject *)&type_object); \
 \
        return module; \
    }


#define PYTHON_OBJECT(name, tom) \
    OBJECT_DEF(tom)              \
    OBJECT_INIT(tom)             \
    OBJECT_DEL()                 \
    OBJECT_DIGESTSIZE()          \
    OBJECT_BLOCKSIZE()           \
    OBJECT_NAME(tom)             \
    OBJECT_UPDATE(tom)           \
    OBJECT_DIGEST(tom)           \
    OBJECT_HEXDIGEST(tom)        \
    OBJECT_COPY()                \
    OBJECT_GETSETER_DEF()        \
    OBJECT_METHODS_DEF()         \
    OBJECT_TYPE(name)            \
    OBJECT_REGISTER(name, tom)

#endif
