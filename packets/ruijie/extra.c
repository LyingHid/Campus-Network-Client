#include <Python.h>
#include "extra.h"

static PyMethodDef ExtraMethods[] = {
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef spammodule = {
   PyModuleDef_HEAD_INIT,
   "extra",   /* name of module */
   NULL,      /* module documentation, may be NULL */
   -1,        /* size of per-interpreter state of the module,
                or -1 if the module keeps state in global variables. */
   ExtraMethods
};

PyMODINIT_FUNC PyInit_extra(void)
{
    // TODO: graceful cleanup when NULL
    PyObject *module = PyModule_Create(&spammodule);
    if(module == NULL) return NULL;

    if(ruijie_md5_register(module) == NULL) return NULL;
    if(ruijie_whirlpool_register(module) == NULL) return NULL;
    if(ruijie_sha1_register(module) == NULL) return NULL;
    if(ruijie_ripemd128_register(module) == NULL) return NULL;

    return module;
}
