#include <Python.h>
#include "extra.h"


static PyMethodDef methods[] = { {NULL, NULL, 0, NULL} };

static struct PyModuleDef module_def = {
   PyModuleDef_HEAD_INIT,
   "extra", NULL, -1, methods
};


/* TODO: self test script
'ruijie_md5' 64 16
b'1234' -> '83eb3436ef12611786c422517e77b7f7'

ruijie_ripemd128 64 16
b'1234' -> '444412cf67d16d24b6235a32bcd5bb3c'

ruijie_sha1 64 20
b'1234' -> '01bc5b5f22a554bba4f1dab797b4ce5c81095a38'

ruijie_tiger 64 24
b'1234' -> '3a4d39536abf29c3b4ff6567758dee1f9c86be72cba480fc'

ruijie_whirlpool 64 64
b'1234' -> '74255664ece43136922ed23790cec0d46c15f7e8e3c768368cd3d131df5eebb5115df47c8252ffd567507c13ed0ecfeed55794648378e3d9010e7317322f70d0'
*/


PyMODINIT_FUNC PyInit_extra(void)
{
    // TODO: graceful cleanup when NULL
    PyObject *module = PyModule_Create(&module_def);
    if(module == NULL) return NULL;

    if(ruijie_data_register(module) == NULL) return NULL;
    if(ruijie_md5_register(module) == NULL) return NULL;
    if(ruijie_whirlpool_register(module) == NULL) return NULL;
    if(ruijie_sha1_register(module) == NULL) return NULL;
    if(ruijie_ripemd128_register(module) == NULL) return NULL;
    if(ruijie_tiger_register(module) == NULL) return NULL;

    return module;
}
