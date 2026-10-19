#include "Python.h"
#include "asdl.h"
#include <stddef.h>             /* offsetof */

/* The room for a sequence of one element: sizeof(asdl_seq) where elements
   is declared [1], but not where it is a flexible array (Py_VAR_ARRAY). */
#define ASDL_SEQ_ONE (offsetof(asdl_seq, elements) + sizeof(void *))

asdl_seq *
asdl_seq_new(int size, PyArena *arena)
{
    asdl_seq *seq = NULL;
    size_t n = (size ? (sizeof(void *) * (size - 1)) : 0);

    /* check size is sane */
    if (size < 0 || size == INT_MIN ||
        (size && ((size - 1) > (PY_SIZE_MAX / sizeof(void *))))) {
        PyErr_NoMemory();
        return NULL;
    }

    /* check if size can be added safely */
    if (n > PY_SIZE_MAX - ASDL_SEQ_ONE) {
        PyErr_NoMemory();
        return NULL;
    }

    n += ASDL_SEQ_ONE;

    seq = (asdl_seq *)PyArena_Malloc(arena, n);
    if (!seq) {
        PyErr_NoMemory();
        return NULL;
    }
    memset(seq, 0, n);
    seq->size = size;
    return seq;
}

asdl_int_seq *
asdl_int_seq_new(int size, PyArena *arena)
{
    asdl_int_seq *seq = NULL;
    size_t n = (size ? (sizeof(void *) * (size - 1)) : 0);

    /* check size is sane */
    if (size < 0 || size == INT_MIN ||
        (size && ((size - 1) > (PY_SIZE_MAX / sizeof(void *))))) {
            PyErr_NoMemory();
            return NULL;
    }

    /* check if size can be added safely */
    if (n > PY_SIZE_MAX - ASDL_SEQ_ONE) {
        PyErr_NoMemory();
        return NULL;
    }

    n += ASDL_SEQ_ONE;

    seq = (asdl_int_seq *)PyArena_Malloc(arena, n);
    if (!seq) {
        PyErr_NoMemory();
        return NULL;
    }
    memset(seq, 0, n);
    seq->size = size;
    return seq;
}
