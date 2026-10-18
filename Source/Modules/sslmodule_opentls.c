/*
 * Amiga _ssl: CPython 2.7 ssl.py API on opentls.library (API version 1).
 *
 * Selected with -DPYAMIGA_USE_OPENTLS (SSL_CFLAGS_OPENTLS in
 * Modules/plugin/vmakefile, the default). OpenTLS is the AmigaChrome
 * Team's TLS client: BearSSL with opencrypto.library doing the maths, which
 * AmigaChrome runs on its x86 or ARM64 cores. On a real Amiga it all runs
 * as 68k code. docs/AutoDocs-OpenTLS.md in DalsinAI/openamigatls is the API.
 *
 * Socket model:
 *   - OT_SetSocket gets the AmiTCP id (PyHost->fn_socket_native_fd) and the
 *     host's own SocketBase, since opentls.library calls recv()/send()
 *     through the base the socket belongs to.
 *   - Every OpenTLS call runs with the socket non-blocking (host
 *     fn_socket_set_nbio, D7-safe IoctlSocket). OTERR_WOULDBLOCK is waited
 *     out here with 1 s WaitSelect slices, so Ctrl-C and socket timeouts
 *     work, then the call is made again. After each call the socket goes
 *     back to the mode Python gave it.
 *   - OTERR_WOULDBLOCK does not say whether OpenTLS wants to read or to
 *     write. Reads and the handshake wait for readable, writes for
 *     writable; a slice that ends with nothing ready just calls again, so a
 *     wrong guess costs at most one slice.
 *
 * Python semantics kept:
 *   - A new context trusts nothing (OTCF_NO_SYSTEM_TRUST) until
 *     load_verify_locations() or set_default_verify_paths() /
 *     load_default_certs(), as CPython's does. The system trust store is
 *     S:OpenTLS/ca-bundle.pem plus the .pem files in ENVARC:OpenTLS/certs.
 *   - CERT_NONE is OTV_NONE. CERT_OPTIONAL and CERT_REQUIRED check the
 *     chain and dates; the host name too when check_hostname is on and a
 *     server_hostname was given (OTV_FULL), as ssl.py's match_hostname
 *     would. getpeercert() reads the certificate's DER here, so
 *     match_hostname sees the real subjectAltName.
 *   - wrap_socket() without server_hostname sends no SNI, as CPython.
 *   - PROTOCOL_TLS / PROTOCOL_SSLv23 means TLS 1.2 and up: OpenTLS's
 *     floor. PROTOCOL_TLSv1 and TLSv1_1 still work for old servers.
 *
 * Not offered by OpenTLS API version 1: server sockets, client
 * certificates (load_cert_chain), NPN, a capath directory loader.
 *
 * C89 / ANSI; plugin FAR data; no doubles in the plugin (timeouts are IEEE
 * bit patterns handed to the host). Builds with VBCC (opentls.library's
 * inline/opentls_protos.h) and GCC (inline/opentls.h).
 */
#include "Python.h"

#include <exec/types.h>
#include <exec/libraries.h>
#include <exec/execbase.h>
#include <dos/dosextens.h>
#include <proto/exec.h>
#include <libraries/opentls.h>
#include <proto/opentls.h>
#include <string.h>

#include "socketmodule.h"

#ifdef PYAMIGA_PLUGIN_BUILD
#include "pyamiga_plugin.h"
#include "pyamiga_redir.h"
#endif

struct Library *OpenTLSBase = NULL;

enum py_ssl_error {
    PY_SSL_ERROR_NONE,
    PY_SSL_ERROR_SSL,
    PY_SSL_ERROR_WANT_READ,
    PY_SSL_ERROR_WANT_WRITE,
    PY_SSL_ERROR_WANT_X509_LOOKUP,
    PY_SSL_ERROR_SYSCALL,
    PY_SSL_ERROR_ZERO_RETURN,
    PY_SSL_ERROR_WANT_CONNECT,
    PY_SSL_ERROR_EOF,
    PY_SSL_ERROR_INVALID_ERROR_CODE
};

enum py_ssl_server_or_client {
    PY_SSL_CLIENT,
    PY_SSL_SERVER
};

enum py_ssl_cert_requirements {
    PY_SSL_CERT_NONE,
    PY_SSL_CERT_OPTIONAL,
    PY_SSL_CERT_REQUIRED
};

/* Match CPython 2.7 numbering (ssl.py PROTOCOL_*). */
enum py_ssl_version {
    PY_SSL_VERSION_SSL2 = 0,
    PY_SSL_VERSION_SSL3 = 1,
    PY_SSL_VERSION_TLS = 2,
    PY_SSL_VERSION_TLS1 = 3,
    PY_SSL_VERSION_TLS1_1 = 4,
    PY_SSL_VERSION_TLS1_2 = 5
};

#define PYSSL_OP_BIT(n) (1UL << (n))
#define PYSSL_OP_TLSEXT_PADDING              PYSSL_OP_BIT(4)
#define PYSSL_OP_SAFARI_ECDHE_ECDSA_BUG      PYSSL_OP_BIT(6)
#define PYSSL_OP_DONT_INSERT_EMPTY_FRAGMENTS PYSSL_OP_BIT(11)
#define PYSSL_OP_NO_COMPRESSION              PYSSL_OP_BIT(17)
#define PYSSL_OP_ENABLE_MIDDLEBOX_COMPAT     PYSSL_OP_BIT(20)
#define PYSSL_OP_CIPHER_SERVER_PREFERENCE    PYSSL_OP_BIT(22)
#define PYSSL_OP_NO_SSLv3                    PYSSL_OP_BIT(25)
#define PYSSL_OP_NO_TLSv1                    PYSSL_OP_BIT(26)
#define PYSSL_OP_NO_TLSv1_2                  PYSSL_OP_BIT(27)
#define PYSSL_OP_NO_TLSv1_1                  PYSSL_OP_BIT(28)
#define PYSSL_OP_NO_TLSv1_3                  PYSSL_OP_BIT(29)
#define PYSSL_OP_CRYPTOPRO_TLSEXT_BUG        PYSSL_OP_BIT(31)
#define PYSSL_OP_ALL (PYSSL_OP_CRYPTOPRO_TLSEXT_BUG | \
    PYSSL_OP_DONT_INSERT_EMPTY_FRAGMENTS | \
    PYSSL_OP_TLSEXT_PADDING | PYSSL_OP_SAFARI_ECDHE_ECDSA_BUG)

#define PYSSL_OP_DEFAULT ( \
    (PYSSL_OP_ALL & ~PYSSL_OP_DONT_INSERT_EMPTY_FRAGMENTS) | \
    PYSSL_OP_NO_SSLv3 | PYSSL_OP_NO_COMPRESSION | \
    PYSSL_OP_CIPHER_SERVER_PREFERENCE)

/* The system trust store (AutoDocs-OpenTLS.md, "The trust store"). */
static const char pyssl_ca_bundle[] = "S:OpenTLS/ca-bundle.pem";
static const char pyssl_ca_bundle_envarc[] = "ENVARC:OpenTLS/ca-bundle.pem";
static const char pyssl_ca_dir[] = "ENVARC:OpenTLS/certs";

/* Used when wrap_socket() has no server_hostname: an address literal, so
 * OpenTLS sends no SNI. The verify mode is never OTV_FULL then, so the
 * name is not checked against the certificate. */
static const char pyssl_no_sni[] = "0.0.0.0";

/* Largest TLS record's payload: one OT_Read never gives more. */
#define PYSSL_READ_MAX 16384

static PyObject *PySSLErrorObject;
static PyObject *PySSLZeroReturnErrorObject;
static PyObject *PySSLWantReadErrorObject;
static PyObject *PySSLWantWriteErrorObject;
static PyObject *PySSLSyscallErrorObject;
static PyObject *PySSLEOFErrorObject;

typedef struct {
    PyObject_HEAD
    struct OTContext *ctx;      /* built at the first wrap (ctx_build) */
    int live;                   /* _SSLSockets using ctx */
    int dirty;                  /* protocol or options changed since */
    int check_hostname;
    int verify_mode;
    unsigned long options;
    unsigned long verify_flags;
    int proto_version;
    int system_trust;           /* set_default_verify_paths() was called */
    long trust_count;           /* certificates added, for cert_store_stats */
    char *alpn;                 /* comma-separated, or NULL */
    PyObject *cafiles;          /* list of str, or NULL */
    PyObject *cadata;           /* list of str, or NULL */
} PySSLContext;

typedef struct {
    PyObject_HEAD
    PySSLContext *ctx;
    PySocketSockObject *Socket;
    struct OTConnection *conn;
    int posix_fd;
    int native_fd;
    int handshake_done;
    int verify_mode;
    enum py_ssl_server_or_client socket_type;
    char hostname[256];
} PySSLSocket;

static PyTypeObject PySSLContext_Type;
static PyTypeObject PySSLSocket_Type;

typedef struct {
    int nid;
    const char *sn;
    const char *ln;
    const char *oid;
} pyssl_asn1_obj;

/* CPython NIDs used by ssl.py Purpose.* at import. */
static const pyssl_asn1_obj pyssl_asn1_table[] = {
    {129, "serverAuth", "TLS Web Server Authentication",
     "1.3.6.1.5.5.7.3.1"},
    {130, "clientAuth", "TLS Web Client Authentication",
     "1.3.6.1.5.5.7.3.2"},
    {13, "CN", "commonName", "2.5.4.3"},
    {0, NULL, NULL, NULL}
};

/* ------------------------------------------------------------------ */
/* Small helpers (the plugin runtime has no strchr / strncmp / ctype). */

static PyObject *
ssl_nomem(void)
{
    PyErr_SetString(PyExc_MemoryError, "out of memory");
    return NULL;
}

static char *
ssl_strdup(const char *s)
{
    size_t n;
    char *p;

    n = strlen(s);
    p = (char *)PyMem_Malloc(n + 1);
    if (p != NULL)
        memcpy(p, s, n + 1);
    return p;
}

static int
ssl_contains(const char *hay, const char *needle)
{
    size_t i;
    size_t j;

    if (hay == NULL)
        return 0;
    for (i = 0; hay[i] != '\0'; i++) {
        for (j = 0; needle[j] != '\0' && hay[i + j] == needle[j]; j++)
            ;
        if (needle[j] == '\0')
            return 1;
    }
    return 0;
}

static PyObject *
ssl_list_to_tuple(PyObject *list)
{
    Py_ssize_t n;
    Py_ssize_t i;
    PyObject *t;
    PyObject *item;

    n = PyList_GET_SIZE(list);
    t = PyTuple_New(n);
    if (t == NULL)
        return NULL;
    for (i = 0; i < n; i++) {
        item = PyList_GET_ITEM(list, i);
        Py_INCREF(item);
        PyTuple_SET_ITEM(t, i, item);
    }
    return t;
}

/* ------------------------------------------------------------------ */
/* Errors */

static const char *
ot_text(struct OTConnection *conn, LONG rc)
{
    CONST_STRPTR s;

    s = NULL;
    if (OpenTLSBase == NULL)
        return "opentls.library is not open";
    if (conn != NULL)
        s = OT_GetErrorText(conn);
    if (s == NULL || s[0] == '\0')
        s = OT_ErrorString(rc);
    if (s == NULL || s[0] == '\0')
        return "OpenTLS error";
    return (const char *)s;
}

static int
ot_is_cert_error(LONG rc)
{
    return (rc == OTERR_UNTRUSTED || rc == OTERR_HOSTNAME
            || rc == OTERR_EXPIRED || rc == OTERR_BADCERT
            || rc == OTERR_TRUSTSTORE || rc == OTERR_PINNED);
}

/* Raise the ssl.py exception for an OpenTLS result. `writing` picks
 * SSLWantWriteError over SSLWantReadError for OTERR_WOULDBLOCK. */
static PyObject *
ot_set_error(struct OTConnection *conn, LONG rc, const char *where,
             int writing)
{
    char buf[400];
    const char *es;
    PyObject *exc;
    PyObject *v;
    enum py_ssl_error p;

    exc = PySSLErrorObject;
    p = PY_SSL_ERROR_SSL;
    if (rc == OTERR_WOULDBLOCK) {
        if (writing) {
            p = PY_SSL_ERROR_WANT_WRITE;
            exc = PySSLWantWriteErrorObject;
            es = "The operation did not complete (write)";
        } else {
            p = PY_SSL_ERROR_WANT_READ;
            exc = PySSLWantReadErrorObject;
            es = "The operation did not complete (read)";
        }
    } else if (rc == OTERR_CLOSED) {
        /* The peer closed without close_notify: ssl.py's
         * suppress_ragged_eofs turns this into "". */
        p = PY_SSL_ERROR_EOF;
        exc = PySSLEOFErrorObject;
        es = "EOF occurred in violation of protocol";
    } else if (ot_is_cert_error(rc)) {
        PyOS_snprintf(buf, sizeof(buf),
                      "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify "
                      "failed: %s (%s, OpenTLS %ld)",
                      ot_text(conn, rc), where, (long)rc);
        es = buf;
    } else if (rc == OTERR_IO) {
        p = PY_SSL_ERROR_SYSCALL;
        exc = PySSLSyscallErrorObject;
        PyOS_snprintf(buf, sizeof(buf), "%s: %s (OpenTLS %ld)",
                      where, ot_text(conn, rc), (long)rc);
        es = buf;
    } else {
        PyOS_snprintf(buf, sizeof(buf), "%s: %s (OpenTLS %ld)",
                      where, ot_text(conn, rc), (long)rc);
        es = buf;
    }
    v = Py_BuildValue("(is)", (int)p, es);
    if (v == NULL)
        return NULL;
    PyErr_SetObject(exc, v);
    Py_DECREF(v);
    return NULL;
}

/* ------------------------------------------------------------------ */
/* Waiting on the socket. Timeouts stay IEEE bit patterns: the plugin
 * links no soft-float, so the host does all double maths. */

#ifdef PYAMIGA_PLUGIN_BUILD
/* 1.0 as a big-endian IEEE-754 double. */
static const unsigned char ssl_slice_1s[8] = {
    0x3F, 0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
#endif

enum {
    SSLW_OK,            /* ready, or a slice passed: call OpenTLS again */
    SSLW_NONBLOCKING,   /* Python socket has timeout 0: raise SSLWant* */
    SSLW_TIMEOUT,       /* the socket's timeout passed */
    SSLW_CLOSED,        /* WaitSelect failed */
    SSLW_SIGNAL         /* Ctrl-C: exception already set */
};

typedef struct {
    int mode;                   /* <0 blocking, 0 non-blocking, >0 timeout */
    unsigned char deadline[8];
} ssl_wait_state;

static void
ssl_wait_begin(PySocketSockObject *sock, ssl_wait_state *w)
{
#ifdef PYAMIGA_PLUGIN_BUILD
    unsigned char tbits[8];

    memcpy(tbits, &sock->sock_timeout, 8);
    w->mode = PyAmiga_Host->fn_sock_timeout_cmp0(tbits);
    if (w->mode > 0)
        PyAmiga_Host->fn_sock_deadline_init(tbits, w->deadline);
#else
    (void)sock;
    w->mode = -1;
#endif
}

static int
ssl_wait(PySSLSocket *self, ssl_wait_state *w, int writing)
{
#ifdef PYAMIGA_PLUGIN_BUILD
    unsigned char remain[8];
    int rc;

    if (w->mode == 0)
        return SSLW_NONBLOCKING;
    if (self->posix_fd < 0)
        return SSLW_CLOSED;
    rc = PyAmiga_Host->fn_sock_select1(self->posix_fd, writing,
                                       ssl_slice_1s);
    if (rc < 0)
        return SSLW_CLOSED;
    if (PyErr_CheckSignals())
        return SSLW_SIGNAL;
    if (w->mode > 0
        && PyAmiga_Host->fn_sock_deadline_remaining(w->deadline, remain))
        return SSLW_TIMEOUT;
    return SSLW_OK;
#else
    (void)self;
    (void)w;
    (void)writing;
    return SSLW_CLOSED;
#endif
}

/* Non-blocking around each OpenTLS call; back to Python's mode after. */
static void
ssl_nbio(PySSLSocket *self, int on)
{
#ifdef PYAMIGA_PLUGIN_BUILD
    if (self->posix_fd < 0 || PyAmiga_Host == NULL
        || PyAmiga_Host->fn_socket_set_nbio == NULL)
        return;
    (void)PyAmiga_Host->fn_socket_set_nbio(self->posix_fd, on);
#else
    (void)self;
    (void)on;
#endif
}

static void
ssl_nbio_restore(PySSLSocket *self, ssl_wait_state *w)
{
    /* CPython: timeout None is a blocking socket; 0 or more is
     * non-blocking with select() doing the waiting. */
    ssl_nbio(self, w->mode >= 0);
}

static PyObject *
ssl_wait_error(PySSLSocket *self, int st, LONG rc, const char *where,
               int writing)
{
    if (st == SSLW_SIGNAL)
        return NULL;
    if (st == SSLW_NONBLOCKING)
        return ot_set_error(self->conn, rc, where, writing);
    if (st == SSLW_TIMEOUT) {
        PyErr_SetString(PySSLErrorObject, writing
                        ? "The write operation timed out"
                        : "The read operation timed out");
        return NULL;
    }
    PyErr_SetString(PySSLErrorObject, "Underlying socket has been closed.");
    return NULL;
}

/* ------------------------------------------------------------------ */
/* The library */

static int
opentls_open(void)
{
    struct Process *pr;
    APTR oldwin;

    if (OpenTLSBase != NULL)
        return 0;
#ifdef PYAMIGA_PLUGIN_BUILD
    if (PyAmiga_Host == NULL || PyAmiga_Host->ptr_SocketBase == NULL) {
        PyErr_SetString(PyExc_ImportError,
                        "opentls.library needs the host's SocketBase "
                        "(import _socket first)");
        return -1;
    }
#endif
    pr = (struct Process *)FindTask(NULL);
    oldwin = pr->pr_WindowPtr;
    pr->pr_WindowPtr = (APTR)-1L;
    OpenTLSBase = OpenLibrary((CONST_STRPTR)OPENTLSLIB_NAME,
                              OPENTLSLIB_VERSION);
    pr->pr_WindowPtr = oldwin;
    if (OpenTLSBase == NULL) {
        PyErr_SetString(PyExc_ImportError,
                        "_ssl needs opentls.library 1 or later in LIBS: "
                        "(with opencrypto.library); OpenUp installs both");
        return -1;
    }
    /* Left open: an atexit CloseLibrary races socket deallocation. */
    return 0;
}

static void *
ssl_socketbase(void)
{
#ifdef PYAMIGA_PLUGIN_BUILD
    return (PyAmiga_Host != NULL) ? PyAmiga_Host->ptr_SocketBase : NULL;
#else
    return NULL;
#endif
}

static int
ssl_native_fd(int posix_fd)
{
#ifdef PYAMIGA_PLUGIN_BUILD
    if (PyAmiga_Host == NULL || PyAmiga_Host->fn_socket_native_fd == NULL)
        return -1;
    return PyAmiga_Host->fn_socket_native_fd(posix_fd);
#else
    return posix_fd;
#endif
}

/* ------------------------------------------------------------------ */
/* Contexts */

static int
ctx_versions(PySSLContext *self, LONG *minv, LONG *maxv)
{
    unsigned long o;
    LONG lo;
    LONG hi;

    o = self->options;
    switch (self->proto_version) {
    case PY_SSL_VERSION_TLS1:
        lo = hi = OT_TLS10;
        break;
    case PY_SSL_VERSION_TLS1_1:
        lo = hi = OT_TLS11;
        break;
    case PY_SSL_VERSION_TLS1_2:
        lo = hi = OT_TLS12;
        break;
    default:
        /* TLS 1.2 and whatever the library has above it. */
        lo = OT_TLS12;
        hi = 0;
        if (o & PYSSL_OP_NO_TLSv1_2) {
            /* Only an explicit opt-out of 1.2 brings 1.0/1.1 back. */
            lo = (o & PYSSL_OP_NO_TLSv1) ? OT_TLS11 : OT_TLS10;
            hi = (o & PYSSL_OP_NO_TLSv1_1) ? OT_TLS10 : OT_TLS11;
            if ((o & PYSSL_OP_NO_TLSv1) && (o & PYSSL_OP_NO_TLSv1_1))
                return -1;
        }
        break;
    }
    if (hi != 0 && lo == hi) {
        if ((lo == OT_TLS10 && (o & PYSSL_OP_NO_TLSv1))
            || (lo == OT_TLS11 && (o & PYSSL_OP_NO_TLSv1_1))
            || (lo == OT_TLS12 && (o & PYSSL_OP_NO_TLSv1_2)))
            return -1;
    }
    *minv = lo;
    *maxv = hi;
    return 0;
}

static int
ctx_add_file(PySSLContext *self, const char *path, int quiet)
{
    LONG n;

    n = OT_AddTrustFile(self->ctx, (CONST_STRPTR)path);
    if (n < 0) {
        if (quiet)
            return 0;
        ot_set_error(NULL, n, path, 0);
        return -1;
    }
    self->trust_count += n;
    return 0;
}

static int
ctx_add_pem(PySSLContext *self, PyObject *data)
{
    LONG n;

    n = OT_AddTrustPEM(self->ctx, (CONST_APTR)PyString_AsString(data),
                       (LONG)PyString_Size(data));
    if (n < 0) {
        ot_set_error(NULL, n, "cadata", 0);
        return -1;
    }
    self->trust_count += n;
    return 0;
}

/* For a context already in use when set_default_verify_paths() came: the
 * CA bundle, as OpenTLS's own system store would read it. A context made
 * after that reads the system store itself, ENVARC:OpenTLS/certs too. */
static int
ctx_add_system_trust(PySSLContext *self)
{
    long before;

    before = self->trust_count;
    if (ctx_add_file(self, pyssl_ca_bundle, 1) < 0)
        return -1;
    if (self->trust_count == before)
        return ctx_add_file(self, pyssl_ca_bundle_envarc, 1);
    return 0;
}

/* Make the OpenTLS context, or remake it when the protocol or options
 * changed and no socket is using it. Called at each wrap. */
static int
ctx_build(PySSLContext *self)
{
    struct OTContextConfig cfg;
    struct OTContext *c;
    LONG err;
    LONG minv;
    LONG maxv;
    Py_ssize_t i;

    if (self->ctx != NULL && (!self->dirty || self->live > 0))
        return 0;
    if (ctx_versions(self, &minv, &maxv) < 0) {
        PyErr_SetString(PySSLErrorObject,
                        "no TLS version left: the protocol and the OP_NO_* "
                        "options rule out all of them");
        return -1;
    }
    memset(&cfg, 0, sizeof(cfg));
    cfg.Size = sizeof(cfg);
    cfg.Flags = self->system_trust ? 0 : OTCF_NO_SYSTEM_TRUST;
    cfg.MinVersion = minv;
    cfg.MaxVersion = maxv;
    err = OTERR_OK;
    c = OT_NewContext(&cfg, &err);
    if (c == NULL) {
        ot_set_error(NULL, err, "OT_NewContext", 0);
        return -1;
    }
    if (self->ctx != NULL)
        OT_FreeContext(self->ctx);
    self->ctx = c;
    self->dirty = 0;
    self->trust_count = 0;
    if (self->cafiles != NULL) {
        for (i = 0; i < PyList_GET_SIZE(self->cafiles); i++) {
            if (ctx_add_file(self,
                    PyString_AsString(PyList_GET_ITEM(self->cafiles, i)),
                    0) < 0) {
                self->dirty = 1;
                return -1;
            }
        }
    }
    if (self->cadata != NULL) {
        for (i = 0; i < PyList_GET_SIZE(self->cadata); i++) {
            if (ctx_add_pem(self, PyList_GET_ITEM(self->cadata, i)) < 0) {
                self->dirty = 1;
                return -1;
            }
        }
    }
    return 0;
}

static int
ctx_remember(PyObject **listp, PyObject *item)
{
    if (*listp == NULL) {
        *listp = PyList_New(0);
        if (*listp == NULL)
            return -1;
    }
    return PyList_Append(*listp, item);
}

/* ------------------------------------------------------------------ */
/* Sockets */

static LONG
ssl_verify_for(int verify_mode, int check_hostname, const char *hostname)
{
    if (verify_mode == PY_SSL_CERT_NONE)
        return OTV_NONE;
    if (check_hostname && hostname[0] != '\0')
        return OTV_FULL;
    return OTV_NO_HOSTNAME;
}

static PySSLSocket *
newPySSLSocket(PySSLContext *sslctx, PySocketSockObject *sock,
               enum py_ssl_server_or_client socket_type,
               char *server_hostname)
{
    PySSLSocket * volatile selfv;
    PySSLSocket *self;
    struct OTConnection *conn;
    LONG err;
    LONG rc;
    LONG vmode;
    int posix_fd;
    int nfd;
    char host[256];

    if (socket_type == PY_SSL_SERVER) {
        PyErr_SetString(PyExc_NotImplementedError,
                        "OpenTLS is a TLS client library");
        return NULL;
    }
    /* Copy what comes from the arguments before any host trampoline or
     * library call: 68k scratch registers do not survive them. */
    host[0] = '\0';
    if (server_hostname != NULL && server_hostname[0] != '\0') {
        strncpy(host, server_hostname, sizeof(host) - 1);
        host[sizeof(host) - 1] = '\0';
    }
    posix_fd = sock->sock_fd;
    nfd = ssl_native_fd(posix_fd);
    if (nfd < 0) {
        PyErr_SetString(PySSLErrorObject, "invalid socket fd");
        return NULL;
    }
    if (ssl_socketbase() == NULL) {
        PyErr_SetString(PySSLErrorObject, "no bsdsocket.library base");
        return NULL;
    }
    if (ctx_build(sslctx) < 0)
        return NULL;

    self = PyObject_New(PySSLSocket, &PySSLSocket_Type);
    if (self == NULL)
        return NULL;
    selfv = self;
    selfv->ctx = sslctx;
    Py_INCREF(sslctx);
    selfv->Socket = NULL;
    selfv->conn = NULL;
    selfv->posix_fd = posix_fd;
    selfv->native_fd = nfd;
    selfv->handshake_done = 0;
    selfv->verify_mode = sslctx->verify_mode;
    selfv->socket_type = socket_type;
    memcpy(selfv->hostname, host, sizeof(host));

    err = OTERR_OK;
    conn = OT_NewConnection(selfv->ctx->ctx,
                            (CONST_STRPTR)(selfv->hostname[0] != '\0'
                                           ? selfv->hostname
                                           : pyssl_no_sni),
                            &err);
    self = selfv;
    if (conn == NULL) {
        ot_set_error(NULL, err, "OT_NewConnection", 0);
        Py_DECREF(self);
        return NULL;
    }
    self->conn = conn;
    self->ctx->live++;

    rc = OT_SetSocket(conn, (LONG)self->native_fd,
                      (struct Library *)ssl_socketbase());
    if (rc == OTERR_OK) {
        vmode = ssl_verify_for(self->verify_mode, self->ctx->check_hostname,
                               self->hostname);
        rc = OT_SetVerify(conn, vmode);
    }
    if (rc == OTERR_OK && self->ctx->alpn != NULL)
        rc = OT_SetALPN(conn, (CONST_STRPTR)self->ctx->alpn);
    self = selfv;
    if (rc != OTERR_OK) {
        ot_set_error(self->conn, rc, "wrap_socket", 0);
        Py_DECREF(self);
        return NULL;
    }
    self->Socket = sock;
    Py_INCREF(sock);
    return self;
}

static void
PySSL_dealloc(PySSLSocket *self)
{
    struct OTConnection *conn;
    PySSLContext *ctx;
    PySocketSockObject *sock;

    conn = self->conn;
    ctx = self->ctx;
    sock = self->Socket;
    self->conn = NULL;
    self->ctx = NULL;
    self->Socket = NULL;
    /* OpenTLS never closes the socket; Python owns it. */
    if (conn != NULL) {
        OT_FreeConnection(conn);
        if (ctx != NULL && ctx->live > 0)
            ctx->live--;
    }
    Py_XDECREF(ctx);
    Py_XDECREF(sock);
    PyObject_Del(self);
}

static int
ssl_check_open(PySSLSocket *self)
{
    if (self->Socket == NULL) {
        PyErr_SetString(PySSLErrorObject, "Underlying socket has been closed.");
        return -1;
    }
    if (self->conn == NULL) {
        PyErr_SetString(PySSLErrorObject, "TLS connection is closed");
        return -1;
    }
    return 0;
}

static PyObject *
PySSL_SSLdo_handshake(PySSLSocket *self)
{
    PySSLSocket * volatile selfv;
    PySocketSockObject *sock;
    ssl_wait_state w;
    LONG rc;
    int st;

    if (ssl_check_open(self) < 0)
        return NULL;
    if (self->handshake_done) {
        Py_INCREF(Py_None);
        return Py_None;
    }
    selfv = self;
    sock = self->Socket;
    Py_INCREF(sock);
    ssl_wait_begin(sock, &w);
    ssl_nbio(selfv, 1);
    for (;;) {
        rc = OT_Handshake(selfv->conn);
        if (rc != OTERR_WOULDBLOCK)
            break;
        st = ssl_wait(selfv, &w, 0);
        if (st != SSLW_OK) {
            ssl_nbio_restore(selfv, &w);
            Py_DECREF(sock);
            return ssl_wait_error(selfv, st, rc, "do_handshake", 0);
        }
    }
    ssl_nbio_restore(selfv, &w);
    Py_DECREF(sock);
    if (rc != OTERR_OK)
        return ot_set_error(selfv->conn, rc, "do_handshake", 0);
    selfv->handshake_done = 1;
    Py_INCREF(Py_None);
    return Py_None;
}

/* ssl.py with do_handshake_on_connect=False reads or writes first:
 * OpenTLS answers OTERR_STATE before a handshake, so run it here. */
static int
ssl_ensure_handshake(PySSLSocket *self)
{
    PyObject *r;

    if (self->handshake_done)
        return 0;
    r = PySSL_SSLdo_handshake(self);
    if (r == NULL)
        return -1;
    Py_DECREF(r);
    return 0;
}

static PyObject *
PySSL_SSLwrite(PySSLSocket *self, PyObject *args)
{
    PySSLSocket * volatile selfv;
    PySocketSockObject *sock;
    ssl_wait_state w;
    char *data;
    char *copy;
    int len;
    int sent;
    LONG rc;
    int st;

    if (!PyArg_ParseTuple(args, "s#:write", &data, &len))
        return NULL;
    if (ssl_check_open(self) < 0)
        return NULL;
    if (len == 0)
        return PyInt_FromLong(0);
    /* Copy before any host trampoline or library call. */
    copy = (char *)PyMem_Malloc((size_t)len);
    if (copy == NULL)
        return ssl_nomem();
    memcpy(copy, data, (size_t)len);
    if (ssl_ensure_handshake(self) < 0) {
        PyMem_Free(copy);
        return NULL;
    }
    selfv = self;
    sock = self->Socket;
    Py_INCREF(sock);
    ssl_wait_begin(sock, &w);
    ssl_nbio(selfv, 1);
    sent = 0;
    rc = 0;
    while (sent < len) {
        rc = OT_Write(selfv->conn, (CONST_APTR)(copy + sent),
                      (LONG)(len - sent));
        if (rc > 0) {
            sent += (int)rc;
            continue;
        }
        if (rc != OTERR_WOULDBLOCK && rc != 0)
            break;
        st = ssl_wait(selfv, &w, 1);
        if (st == SSLW_NONBLOCKING && sent > 0)
            break;              /* report what went; Python retries */
        if (st != SSLW_OK) {
            ssl_nbio_restore(selfv, &w);
            PyMem_Free(copy);
            Py_DECREF(sock);
            return ssl_wait_error(selfv, st, OTERR_WOULDBLOCK, "write", 1);
        }
    }
    ssl_nbio_restore(selfv, &w);
    PyMem_Free(copy);
    Py_DECREF(sock);
    if (sent == 0 && rc < 0)
        return ot_set_error(selfv->conn, rc, "write", 1);
    return PyInt_FromLong(sent);
}

static PyObject *
PySSL_SSLpending(PySSLSocket *self)
{
    LONG n;

    n = 0;
    if (self->conn != NULL) {
        n = OT_Pending(self->conn);
        if (n < 0)
            n = 0;
    }
    return PyInt_FromLong((long)n);
}

static PyObject *
PySSL_SSLread(PySSLSocket *self, PyObject *args)
{
    PySSLSocket * volatile selfv;
    PySocketSockObject *sock;
    PyObject *buffer;
    PyObject *dest;
    ssl_wait_state w;
    Py_ssize_t buflen;
    void *wbuf;
    char *data;
    int len;
    LONG rc;
    int st;

    buffer = NULL;
    dest = NULL;
    wbuf = NULL;
    len = 1024;
    if (!PyArg_ParseTuple(args, "|iO:read", &len, &buffer))
        return NULL;
    if (len < 0) {
        PyErr_SetString(PyExc_ValueError, "size should not be negative");
        return NULL;
    }
    if (ssl_check_open(self) < 0)
        return NULL;
    if (len > PYSSL_READ_MAX)
        len = PYSSL_READ_MAX;
    if (buffer != NULL && buffer != Py_None) {
        if (PyObject_AsWriteBuffer(buffer, &wbuf, &buflen) < 0)
            return NULL;
        if (len == 0 || buflen < len)
            len = (int)buflen;
    } else {
        buffer = NULL;
    }
    if (len == 0) {
        if (buffer != NULL)
            return PyInt_FromLong(0);
        return PyString_FromStringAndSize("", 0);
    }
    if (ssl_ensure_handshake(self) < 0)
        return NULL;
    if (buffer != NULL) {
        /* The handshake called the host: fetch the buffer again. */
        if (PyObject_AsWriteBuffer(buffer, &wbuf, &buflen) < 0)
            return NULL;
        if (buflen < len)
            len = (int)buflen;
    }
    if (buffer == NULL) {
        dest = PyString_FromStringAndSize(NULL, len);
        if (dest == NULL)
            return NULL;
    }
    selfv = self;
    sock = self->Socket;
    Py_INCREF(sock);
    ssl_wait_begin(sock, &w);
    ssl_nbio(selfv, 1);
    for (;;) {
        data = (dest != NULL) ? PyString_AsString(dest) : (char *)wbuf;
        rc = OT_Read(selfv->conn, (APTR)data, (LONG)len);
        if (rc != OTERR_WOULDBLOCK)
            break;
        st = ssl_wait(selfv, &w, 0);
        if (st != SSLW_OK) {
            ssl_nbio_restore(selfv, &w);
            Py_XDECREF(dest);
            Py_DECREF(sock);
            return ssl_wait_error(selfv, st, rc, "read", 0);
        }
    }
    ssl_nbio_restore(selfv, &w);
    Py_DECREF(sock);
    if (rc < 0) {
        Py_XDECREF(dest);
        return ot_set_error(selfv->conn, rc, "read", 0);
    }
    /* rc == 0: the peer sent close_notify; "" as CPython. */
    if (dest != NULL) {
        if (_PyString_Resize(&dest, (Py_ssize_t)rc) < 0)
            return NULL;
        return dest;
    }
    return PyInt_FromLong((long)rc);
}

static PyObject *
PySSL_SSLshutdown(PySSLSocket *self)
{
    PySSLSocket * volatile selfv;
    PySocketSockObject *sock;
    ssl_wait_state w;
    LONG rc;
    int tries;

    sock = self->Socket;
    if (sock == NULL) {
        PyErr_SetString(PySSLErrorObject, "Underlying socket has been closed.");
        return NULL;
    }
    selfv = self;
    ssl_wait_begin(sock, &w);
    if (self->conn != NULL && self->handshake_done) {
        ssl_nbio(selfv, 1);
        /* close_notify, best effort: OpenTLS does not wait for the
         * peer's, and Python closes the socket anyway. */
        for (tries = 0; tries < 3; tries++) {
            rc = OT_Close(selfv->conn);
            if (rc != OTERR_WOULDBLOCK)
                break;
            if (ssl_wait(selfv, &w, 1) != SSLW_OK) {
                PyErr_Clear();
                break;
            }
        }
    }
    ssl_nbio_restore(selfv, &w);
    /* Hand the plain socket back (ssl.py unwrap); the reference moves. */
    selfv->Socket = NULL;
    return (PyObject *)sock;
}

/* ------------------------------------------------------------------ */
/* getpeercert(): the certificate's DER, read here so the dict has what
 * ssl.match_hostname needs (subjectAltName) and what CPython shows. */

typedef struct {
    const unsigned char *p;     /* contents */
    long len;
    int tag;
} der_item;

/* Read one TLV at *pos within [base, base+end). 0 ok, -1 malformed. */
static int
der_next(const unsigned char *base, long end, long *pos, der_item *it)
{
    long i;
    long len;
    int n;

    i = *pos;
    if (i + 2 > end)
        return -1;
    it->tag = base[i++];
    len = base[i++];
    if (len & 0x80) {
        n = (int)(len & 0x7F);
        if (n < 1 || n > 3 || i + n > end)
            return -1;
        len = 0;
        while (n-- > 0)
            len = (len << 8) | base[i++];
    }
    if (len < 0 || i + len > end)
        return -1;
    it->p = base + i;
    it->len = len;
    *pos = i + len;
    return 0;
}

static int
der_enter(const der_item *outer, int tag, long *pos, der_item *it)
{
    if (der_next(outer->p, outer->len, pos, it) < 0 || it->tag != tag)
        return -1;
    return 0;
}

typedef struct {
    unsigned char oid[9];
    int oidlen;
    const char *name;
} der_attr;

static const der_attr der_attrs[] = {
    {{0x55, 0x04, 0x03}, 3, "commonName"},
    {{0x55, 0x04, 0x06}, 3, "countryName"},
    {{0x55, 0x04, 0x07}, 3, "localityName"},
    {{0x55, 0x04, 0x08}, 3, "stateOrProvinceName"},
    {{0x55, 0x04, 0x0A}, 3, "organizationName"},
    {{0x55, 0x04, 0x0B}, 3, "organizationalUnitName"},
    {{0x55, 0x04, 0x05}, 3, "serialNumber"},
    {{0x55, 0x04, 0x0F}, 3, "businessCategory"},
    {{0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x01}, 9,
     "emailAddress"},
    {{0}, 0, NULL}
};

static const char *
der_attr_name(const der_item *oid)
{
    const der_attr *a;

    for (a = der_attrs; a->name != NULL; a++) {
        if (oid->len == a->oidlen && memcmp(oid->p, a->oid, a->oidlen) == 0)
            return a->name;
    }
    return NULL;
}

static int
der_is_string(int tag)
{
    /* UTF8, Numeric, Printable, T61, IA5, Visible: as bytes. */
    return (tag == 0x0C || tag == 0x12 || tag == 0x13 || tag == 0x14
            || tag == 0x16 || tag == 0x1A);
}

/* Name -> ((('commonName', 'x'),), ...) */
static PyObject *
der_name(const der_item *name)
{
    PyObject *rdns;
    PyObject *attrs;
    PyObject *t;
    der_item set;
    der_item atv;
    der_item oid;
    der_item val;
    long pos;
    long spos;
    long apos;
    const char *an;
    int rc;

    rdns = PyList_New(0);
    if (rdns == NULL)
        return NULL;
    pos = 0;
    while (pos < name->len) {
        if (der_enter(name, 0x31, &pos, &set) < 0)
            goto bad;
        attrs = PyList_New(0);
        if (attrs == NULL)
            goto fail;
        spos = 0;
        while (spos < set.len) {
            if (der_enter(&set, 0x30, &spos, &atv) < 0) {
                Py_DECREF(attrs);
                goto bad;
            }
            apos = 0;
            if (der_enter(&atv, 0x06, &apos, &oid) < 0
                || der_next(atv.p, atv.len, &apos, &val) < 0) {
                Py_DECREF(attrs);
                goto bad;
            }
            an = der_attr_name(&oid);
            if (an == NULL || !der_is_string(val.tag))
                continue;
            t = Py_BuildValue("(ss#)", an, (const char *)val.p,
                              (int)val.len);
            if (t == NULL) {
                Py_DECREF(attrs);
                goto fail;
            }
            rc = PyList_Append(attrs, t);
            Py_DECREF(t);
            if (rc < 0) {
                Py_DECREF(attrs);
                goto fail;
            }
        }
        if (PyList_GET_SIZE(attrs) > 0) {
            t = ssl_list_to_tuple(attrs);
            Py_DECREF(attrs);
            if (t == NULL)
                goto fail;
            rc = PyList_Append(rdns, t);
            Py_DECREF(t);
            if (rc < 0)
                goto fail;
        } else {
            Py_DECREF(attrs);
        }
    }
    t = ssl_list_to_tuple(rdns);
    Py_DECREF(rdns);
    return t;
bad:
    PyErr_SetString(PySSLErrorObject, "malformed name in certificate");
fail:
    Py_DECREF(rdns);
    return NULL;
}

static int
der_digits(const unsigned char *p, int n)
{
    int v;
    int i;

    v = 0;
    for (i = 0; i < n; i++) {
        if (p[i] < '0' || p[i] > '9')
            return -1;
        v = v * 10 + (p[i] - '0');
    }
    return v;
}

/* UTCTime / GeneralizedTime -> "Jan  5 12:00:00 2026 GMT" (OpenSSL's). */
static PyObject *
der_time(const der_item *t)
{
    static const char months[12][4] = {
        "Jan", "Feb", "Mar", "Apr", "May", "Jun",
        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
    };
    const unsigned char *p;
    char buf[32];
    int year;
    int mon;
    int day;
    int hh;
    int mm;
    int ss;

    p = t->p;
    if (t->tag == 0x17 && t->len >= 13) {
        year = der_digits(p, 2);
        if (year < 0)
            goto bad;
        year += (year < 50) ? 2000 : 1900;
        p += 2;
    } else if (t->tag == 0x18 && t->len >= 15) {
        year = der_digits(p, 4);
        p += 4;
    } else {
        goto bad;
    }
    mon = der_digits(p, 2);
    day = der_digits(p + 2, 2);
    hh = der_digits(p + 4, 2);
    mm = der_digits(p + 6, 2);
    ss = der_digits(p + 8, 2);
    if (year < 0 || mon < 1 || mon > 12 || day < 1 || day > 31
        || hh < 0 || mm < 0 || ss < 0)
        goto bad;
    PyOS_snprintf(buf, sizeof(buf), "%s %2d %02d:%02d:%02d %d GMT",
                  months[mon - 1], day, hh, mm, ss, year);
    return PyString_FromString(buf);
bad:
    PyErr_SetString(PySSLErrorObject, "malformed time in certificate");
    return NULL;
}

static PyObject *
der_serial(const der_item *s)
{
    static const char hex[] = "0123456789ABCDEF";
    char buf[130];
    long i;
    int n;

    i = 0;
    while (i < s->len - 1 && s->p[i] == 0)
        i++;
    n = 0;
    for (; i < s->len && n < (int)sizeof(buf) - 2; i++) {
        buf[n++] = hex[s->p[i] >> 4];
        buf[n++] = hex[s->p[i] & 15];
    }
    buf[n] = '\0';
    return PyString_FromString(buf);
}

static PyObject *
der_ip(const unsigned char *p, long len)
{
    char buf[48];

    if (len == 4) {
        PyOS_snprintf(buf, sizeof(buf), "%d.%d.%d.%d",
                      p[0], p[1], p[2], p[3]);
    } else if (len == 16) {
        /* CPython 2.7.18's form: eight groups, upper case, uncompressed. */
        PyOS_snprintf(buf, sizeof(buf), "%X:%X:%X:%X:%X:%X:%X:%X",
                      (p[0] << 8) | p[1], (p[2] << 8) | p[3],
                      (p[4] << 8) | p[5], (p[6] << 8) | p[7],
                      (p[8] << 8) | p[9], (p[10] << 8) | p[11],
                      (p[12] << 8) | p[13], (p[14] << 8) | p[15]);
    } else {
        PyOS_snprintf(buf, sizeof(buf), "<invalid>");
    }
    return PyString_FromString(buf);
}

/* subjectAltName's GeneralNames -> (('DNS', 'x'), ('IP Address', 'y')) */
static PyObject *
der_san(const der_item *octets)
{
    PyObject *list;
    PyObject *t;
    der_item seq;
    der_item gn;
    long pos;
    long gpos;
    int rc;

    pos = 0;
    if (der_next(octets->p, octets->len, &pos, &seq) < 0 || seq.tag != 0x30) {
        PyErr_SetString(PySSLErrorObject, "malformed subjectAltName");
        return NULL;
    }
    list = PyList_New(0);
    if (list == NULL)
        return NULL;
    gpos = 0;
    while (gpos < seq.len) {
        if (der_next(seq.p, seq.len, &gpos, &gn) < 0) {
            Py_DECREF(list);
            PyErr_SetString(PySSLErrorObject, "malformed subjectAltName");
            return NULL;
        }
        t = NULL;
        if (gn.tag == 0x82)
            t = Py_BuildValue("(ss#)", "DNS", (const char *)gn.p,
                              (int)gn.len);
        else if (gn.tag == 0x81)
            t = Py_BuildValue("(ss#)", "email", (const char *)gn.p,
                              (int)gn.len);
        else if (gn.tag == 0x86)
            t = Py_BuildValue("(ss#)", "URI", (const char *)gn.p,
                              (int)gn.len);
        else if (gn.tag == 0x87) {
            PyObject *ip = der_ip(gn.p, gn.len);
            if (ip == NULL) {
                Py_DECREF(list);
                return NULL;
            }
            t = Py_BuildValue("(sO)", "IP Address", ip);
            Py_DECREF(ip);
        } else {
            continue;
        }
        if (t == NULL) {
            Py_DECREF(list);
            return NULL;
        }
        rc = PyList_Append(list, t);
        Py_DECREF(t);
        if (rc < 0) {
            Py_DECREF(list);
            return NULL;
        }
    }
    t = ssl_list_to_tuple(list);
    Py_DECREF(list);
    return t;
}

static int
dict_set_new(PyObject *d, const char *key, PyObject *v)
{
    int rc;

    if (v == NULL)
        return -1;
    rc = PyDict_SetItemString(d, key, v);
    Py_DECREF(v);
    return rc;
}

static PyObject *
der_cert_dict(const unsigned char *der, long derlen)
{
    static const unsigned char oid_san[3] = {0x55, 0x1D, 0x11};
    PyObject *d;
    der_item top;
    der_item cert;
    der_item tbs;
    der_item it;
    der_item validity;
    der_item exts;
    der_item ext;
    der_item part;
    der_item oid;
    der_item val;
    long pos;
    long tpos;
    long vpos;
    long epos;
    long xpos;
    int version;

    pos = 0;
    top.p = der;
    top.len = derlen;
    if (der_enter(&top, 0x30, &pos, &cert) < 0)
        goto bad;
    pos = 0;
    if (der_enter(&cert, 0x30, &pos, &tbs) < 0)
        goto bad;
    d = PyDict_New();
    if (d == NULL)
        return NULL;
    tpos = 0;
    if (der_next(tbs.p, tbs.len, &tpos, &it) < 0)
        goto bad_d;
    version = 1;
    if (it.tag == 0xA0) {               /* [0] EXPLICIT version */
        vpos = 0;
        if (der_enter(&it, 0x02, &vpos, &val) < 0 || val.len != 1)
            goto bad_d;
        version = val.p[0] + 1;
        if (der_next(tbs.p, tbs.len, &tpos, &it) < 0)
            goto bad_d;
    }
    if (it.tag != 0x02)                 /* serialNumber */
        goto bad_d;
    if (dict_set_new(d, "serialNumber", der_serial(&it)) < 0
        || dict_set_new(d, "version", PyInt_FromLong(version)) < 0)
        goto fail_d;
    if (der_enter(&tbs, 0x30, &tpos, &it) < 0)     /* signature AlgId */
        goto bad_d;
    if (der_enter(&tbs, 0x30, &tpos, &it) < 0)     /* issuer */
        goto bad_d;
    if (dict_set_new(d, "issuer", der_name(&it)) < 0)
        goto fail_d;
    if (der_enter(&tbs, 0x30, &tpos, &validity) < 0)
        goto bad_d;
    vpos = 0;
    if (der_next(validity.p, validity.len, &vpos, &it) < 0
        || dict_set_new(d, "notBefore", der_time(&it)) < 0)
        goto fail_d;
    if (der_next(validity.p, validity.len, &vpos, &it) < 0
        || dict_set_new(d, "notAfter", der_time(&it)) < 0)
        goto fail_d;
    if (der_enter(&tbs, 0x30, &tpos, &it) < 0)     /* subject */
        goto bad_d;
    if (dict_set_new(d, "subject", der_name(&it)) < 0)
        goto fail_d;
    /* subjectPublicKeyInfo, then optional [1] [2] [3]. */
    while (tpos < tbs.len) {
        if (der_next(tbs.p, tbs.len, &tpos, &it) < 0)
            goto bad_d;
        if (it.tag != 0xA3)
            continue;
        epos = 0;
        if (der_enter(&it, 0x30, &epos, &exts) < 0)
            goto bad_d;
        epos = 0;
        while (epos < exts.len) {
            if (der_enter(&exts, 0x30, &epos, &ext) < 0)
                goto bad_d;
            xpos = 0;
            if (der_enter(&ext, 0x06, &xpos, &oid) < 0)
                goto bad_d;
            if (oid.len != 3 || memcmp(oid.p, oid_san, 3) != 0)
                continue;
            if (der_next(ext.p, ext.len, &xpos, &part) < 0)
                goto bad_d;
            if (part.tag == 0x01 && der_next(ext.p, ext.len, &xpos,
                                             &part) < 0)
                goto bad_d;               /* skip "critical" */
            if (part.tag != 0x04)
                goto bad_d;
            if (dict_set_new(d, "subjectAltName", der_san(&part)) < 0)
                goto fail_d;
        }
    }
    return d;
bad_d:
    Py_DECREF(d);
bad:
    PyErr_SetString(PySSLErrorObject, "malformed certificate");
    return NULL;
fail_d:
    Py_DECREF(d);
    return NULL;
}

static PyObject *
PySSL_peercert(PySSLSocket *self, PyObject *args)
{
    PyObject *der;
    PyObject *res;
    int binary_mode;
    LONG n;

    binary_mode = 0;
    if (!PyArg_ParseTuple(args, "|i:peer_certificate", &binary_mode))
        return NULL;
    if (!self->handshake_done || self->conn == NULL) {
        PyErr_SetString(PyExc_ValueError, "handshake not done yet");
        return NULL;
    }
    n = OT_GetPeerCertificate(self->conn, NULL, 0);
    if (n <= 0) {
        Py_INCREF(Py_None);
        return Py_None;
    }
    der = PyString_FromStringAndSize(NULL, (Py_ssize_t)n);
    if (der == NULL)
        return NULL;
    n = OT_GetPeerCertificate(self->conn,
                              (APTR)PyString_AsString(der), n);
    if (n <= 0) {
        Py_DECREF(der);
        return ot_set_error(self->conn, n, "getpeercert", 0);
    }
    if (binary_mode)
        return der;
    if (self->verify_mode == PY_SSL_CERT_NONE) {
        /* As CPython: an unchecked certificate gives {}. */
        Py_DECREF(der);
        return PyDict_New();
    }
    res = der_cert_dict((const unsigned char *)PyString_AsString(der),
                        (long)PyString_Size(der));
    Py_DECREF(der);
    return res;
}

static const char *
ssl_proto_name(LONG v)
{
    switch (v) {
    case OT_TLS10: return "TLSv1";
    case OT_TLS11: return "TLSv1.1";
    case OT_TLS12: return "TLSv1.2";
    case OT_TLS13: return "TLSv1.3";
    }
    return NULL;
}

static PyObject *
PySSL_cipher(PySSLSocket *self)
{
    CONST_STRPTR name;
    const char *proto;
    int bits;

    if (!self->handshake_done || self->conn == NULL) {
        Py_INCREF(Py_None);
        return Py_None;
    }
    name = OT_GetCipher(self->conn);
    proto = ssl_proto_name(OT_GetProtocol(self->conn));
    if (name == NULL || name[0] == '\0' || proto == NULL) {
        Py_INCREF(Py_None);
        return Py_None;
    }
    bits = 0;
    if (ssl_contains((const char *)name, "AES128")
        || ssl_contains((const char *)name, "AES_128"))
        bits = 128;
    else if (ssl_contains((const char *)name, "AES256")
             || ssl_contains((const char *)name, "AES_256")
             || ssl_contains((const char *)name, "CHACHA20"))
        bits = 256;
    else if (ssl_contains((const char *)name, "3DES")
             || ssl_contains((const char *)name, "DES-CBC3"))
        bits = 112;
    return Py_BuildValue("(ssi)", (const char *)name, proto, bits);
}

static PyObject *
PySSL_version(PySSLSocket *self)
{
    const char *proto;

    if (!self->handshake_done || self->conn == NULL) {
        Py_INCREF(Py_None);
        return Py_None;
    }
    proto = ssl_proto_name(OT_GetProtocol(self->conn));
    if (proto == NULL) {
        Py_INCREF(Py_None);
        return Py_None;
    }
    return PyString_FromString(proto);
}

static PyObject *
PySSL_selected_npn_protocol(PySSLSocket *self)
{
    (void)self;
    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject *
PySSL_selected_alpn_protocol(PySSLSocket *self)
{
    CONST_STRPTR p;

    if (!self->handshake_done || self->conn == NULL) {
        Py_INCREF(Py_None);
        return Py_None;
    }
    p = OT_GetALPN(self->conn);
    if (p == NULL || p[0] == '\0') {
        Py_INCREF(Py_None);
        return Py_None;
    }
    return PyString_FromString((const char *)p);
}

static PyObject *
PySSL_compression(PySSLSocket *self)
{
    (void)self;
    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject *
PySSL_tls_unique_cb(PySSLSocket *self)
{
    (void)self;
    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject *
PySSL_get_context(PySSLSocket *self, void *closure)
{
    (void)closure;
    Py_INCREF(self->ctx);
    return (PyObject *)self->ctx;
}

static int
PySSL_set_context(PySSLSocket *self, PyObject *value, void *closure)
{
    (void)self;
    (void)value;
    (void)closure;
    PyErr_SetString(PyExc_NotImplementedError,
                    "OpenTLS cannot move a connection to another context");
    return -1;
}

static PyGetSetDef ssl_getsetlist[] = {
    {"context", (getter)PySSL_get_context, (setter)PySSL_set_context, NULL},
    {NULL, NULL, NULL, NULL}
};

static PyMethodDef PySSLMethods[] = {
    {"do_handshake", (PyCFunction)PySSL_SSLdo_handshake, METH_NOARGS, NULL},
    {"write", (PyCFunction)PySSL_SSLwrite, METH_VARARGS, NULL},
    {"read", (PyCFunction)PySSL_SSLread, METH_VARARGS, NULL},
    {"pending", (PyCFunction)PySSL_SSLpending, METH_NOARGS, NULL},
    {"peer_certificate", (PyCFunction)PySSL_peercert, METH_VARARGS, NULL},
    {"cipher", (PyCFunction)PySSL_cipher, METH_NOARGS, NULL},
    {"version", (PyCFunction)PySSL_version, METH_NOARGS, NULL},
    {"selected_npn_protocol", (PyCFunction)PySSL_selected_npn_protocol,
     METH_NOARGS, NULL},
    {"selected_alpn_protocol", (PyCFunction)PySSL_selected_alpn_protocol,
     METH_NOARGS, NULL},
    {"compression", (PyCFunction)PySSL_compression, METH_NOARGS, NULL},
    {"shutdown", (PyCFunction)PySSL_SSLshutdown, METH_NOARGS, NULL},
    {"tls_unique_cb", (PyCFunction)PySSL_tls_unique_cb, METH_NOARGS, NULL},
    {NULL, NULL, 0, NULL}
};

static PyTypeObject PySSLSocket_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "_ssl._SSLSocket",                  /* tp_name */
    sizeof(PySSLSocket),                /* tp_basicsize */
    0,                                  /* tp_itemsize */
    (destructor)PySSL_dealloc,          /* tp_dealloc */
    0,                                  /* tp_print */
    0,                                  /* tp_getattr */
    0,                                  /* tp_setattr */
    0,                                  /* tp_compare */
    0,                                  /* tp_repr */
    0,                                  /* tp_as_number */
    0,                                  /* tp_as_sequence */
    0,                                  /* tp_as_mapping */
    0,                                  /* tp_hash */
    0,                                  /* tp_call */
    0,                                  /* tp_str */
    PyObject_GenericGetAttr,            /* tp_getattro */
    0,                                  /* tp_setattro */
    0,                                  /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT,                 /* tp_flags */
    0,                                  /* tp_doc */
    0,                                  /* tp_traverse */
    0,                                  /* tp_clear */
    0,                                  /* tp_richcompare */
    0,                                  /* tp_weaklistoffset */
    0,                                  /* tp_iter */
    0,                                  /* tp_iternext */
    PySSLMethods,                       /* tp_methods */
    0,                                  /* tp_members */
    ssl_getsetlist,                     /* tp_getset */
    0,                                  /* tp_base */
    0,                                  /* tp_dict */
    0,                                  /* tp_descr_get */
    0,                                  /* tp_descr_set */
    0,                                  /* tp_dictoffset */
    0,                                  /* tp_init */
    PyType_GenericAlloc,                /* tp_alloc */
    0,                                  /* tp_new */
    PyObject_Del                        /* tp_free */
};

/* ------------------------------------------------------------------ */
/* _SSLContext */

static PyObject *
context_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    char *kwlist[2];
    PySSLContext *self;
    PySSLContext * volatile selfv;
    int proto_version;

    kwlist[0] = "protocol";
    kwlist[1] = NULL;
    proto_version = PY_SSL_VERSION_TLS;
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "i:_SSLContext", kwlist,
                                     &proto_version))
        return NULL;
    if (proto_version == PY_SSL_VERSION_SSL2
        || proto_version == PY_SSL_VERSION_SSL3) {
        PyErr_SetString(PyExc_ValueError,
                        "SSLv2 and SSLv3 are not supported by OpenTLS");
        return NULL;
    }
    if (proto_version < PY_SSL_VERSION_TLS
        || proto_version > PY_SSL_VERSION_TLS1_2) {
        PyErr_SetString(PyExc_ValueError, "invalid protocol version");
        return NULL;
    }
    self = (PySSLContext *)type->tp_alloc(type, 0);
    if (self == NULL)
        return NULL;
    selfv = self;
    selfv->ctx = NULL;
    selfv->live = 0;
    selfv->dirty = 0;
    selfv->check_hostname = 0;
    selfv->verify_mode = PY_SSL_CERT_NONE;
    selfv->options = PYSSL_OP_DEFAULT;
    selfv->verify_flags = 0;
    selfv->proto_version = proto_version;
    selfv->system_trust = 0;
    selfv->trust_count = 0;
    selfv->alpn = NULL;
    selfv->cafiles = NULL;
    selfv->cadata = NULL;
    return (PyObject *)selfv;
}

static void
context_dealloc(PySSLContext *self)
{
    /* Sockets hold a reference, so none is alive here. */
    if (self->ctx != NULL)
        OT_FreeContext(self->ctx);
    self->ctx = NULL;
    if (self->alpn != NULL)
        PyMem_Free(self->alpn);
    self->alpn = NULL;
    Py_XDECREF(self->cafiles);
    self->cafiles = NULL;
    Py_XDECREF(self->cadata);
    self->cadata = NULL;
    /* ssl.SSLContext is a heap subclass: the host's subtype_dealloc calls
     * this tp_dealloc. Free through PyObject_Del -> host fn_object_dealloc. */
    PyObject_Del(self);
}

static PyObject *
set_ciphers(PySSLContext *self, PyObject *args)
{
    const char *cipherlist;

    (void)self;
    if (!PyArg_ParseTuple(args, "s:set_ciphers", &cipherlist))
        return NULL;
    /* OpenTLS chooses its own suites (ECDHE with AES-GCM or
     * ChaCha20-Poly1305 first); OpenSSL cipher strings do not apply. */
    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject *
_set_npn_protocols(PySSLContext *self, PyObject *args)
{
    (void)self;
    (void)args;
    PyErr_SetString(PyExc_NotImplementedError,
                    "NPN is not available in OpenTLS (use ALPN)");
    return NULL;
}

/* Wire format (length-prefixed) -> OpenTLS's comma-separated list. */
static PyObject *
_set_alpn_protocols(PySSLContext *self, PyObject *args)
{
    Py_buffer protos;
    const unsigned char *p;
    char *out;
    Py_ssize_t i;
    Py_ssize_t n;
    int k;

    if (!PyArg_ParseTuple(args, "s*:set_alpn_protocols", &protos))
        return NULL;
    p = (const unsigned char *)protos.buf;
    out = (char *)PyMem_Malloc((size_t)protos.len + 1);
    if (out == NULL) {
        PyBuffer_Release(&protos);
        return ssl_nomem();
    }
    n = 0;
    i = 0;
    while (i < protos.len) {
        k = p[i++];
        if (k == 0 || i + k > protos.len) {
            PyMem_Free(out);
            PyBuffer_Release(&protos);
            PyErr_SetString(PyExc_ValueError, "invalid ALPN protocol list");
            return NULL;
        }
        if (n > 0)
            out[n++] = ',';
        memcpy(out + n, p + i, (size_t)k);
        n += k;
        i += k;
    }
    out[n] = '\0';
    PyBuffer_Release(&protos);
    if (self->alpn != NULL)
        PyMem_Free(self->alpn);
    self->alpn = NULL;
    if (n > 0)
        self->alpn = out;
    else
        PyMem_Free(out);
    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject *
get_verify_mode(PySSLContext *self, void *c)
{
    (void)c;
    return PyLong_FromLong(self->verify_mode);
}

static int
set_verify_mode(PySSLContext *self, PyObject *arg, void *c)
{
    int n;

    (void)c;
    if (!PyArg_Parse(arg, "i", &n))
        return -1;
    if (n != PY_SSL_CERT_NONE && n != PY_SSL_CERT_OPTIONAL
        && n != PY_SSL_CERT_REQUIRED) {
        PyErr_SetString(PyExc_ValueError, "invalid value for verify_mode");
        return -1;
    }
    if (n == PY_SSL_CERT_NONE && self->check_hostname) {
        PyErr_SetString(PyExc_ValueError,
                        "Cannot set verify_mode to CERT_NONE when "
                        "check_hostname is enabled.");
        return -1;
    }
    self->verify_mode = n;
    return 0;
}

static PyObject *
get_verify_flags(PySSLContext *self, void *c)
{
    (void)c;
    return PyLong_FromUnsignedLong(self->verify_flags);
}

static int
set_verify_flags(PySSLContext *self, PyObject *arg, void *c)
{
    unsigned long new_flags;

    (void)c;
    if (!PyArg_Parse(arg, "k", &new_flags))
        return -1;
    /* OpenTLS has no CRL checks; the flags are kept for ssl.py. */
    self->verify_flags = new_flags;
    return 0;
}

static PyObject *
get_options(PySSLContext *self, void *c)
{
    (void)c;
    return PyLong_FromUnsignedLong(self->options);
}

static int
set_options(PySSLContext *self, PyObject *arg, void *c)
{
    unsigned long new_opts;

    (void)c;
    if (!PyArg_Parse(arg, "k", &new_opts))
        return -1;
    if (new_opts != self->options)
        self->dirty = 1;
    self->options = new_opts;
    return 0;
}

static PyObject *
get_check_hostname(PySSLContext *self, void *c)
{
    (void)c;
    return PyBool_FromLong(self->check_hostname);
}

static int
set_check_hostname(PySSLContext *self, PyObject *arg, void *c)
{
    int check_hostname;

    (void)c;
    check_hostname = PyObject_IsTrue(arg);
    if (check_hostname < 0)
        return -1;
    if (check_hostname && self->verify_mode == PY_SSL_CERT_NONE) {
        PyErr_SetString(PyExc_ValueError,
                        "check_hostname needs a SSL context with either "
                        "CERT_OPTIONAL or CERT_REQUIRED");
        return -1;
    }
    self->check_hostname = check_hostname;
    return 0;
}

static PyObject *
load_cert_chain(PySSLContext *self, PyObject *args, PyObject *kwds)
{
    (void)self;
    (void)args;
    (void)kwds;
    PyErr_SetString(PyExc_NotImplementedError,
                    "client certificates are not supported by OpenTLS "
                    "API version 1");
    return NULL;
}

static PyObject *
load_verify_locations(PySSLContext *self, PyObject *args, PyObject *kwds)
{
    char *kwlist[4];
    PyObject *cafile;
    PyObject *capath;
    PyObject *cadata;

    kwlist[0] = "cafile";
    kwlist[1] = "capath";
    kwlist[2] = "cadata";
    kwlist[3] = NULL;
    cafile = NULL;
    capath = NULL;
    cadata = NULL;
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|OOO:load_verify_locations",
                                     kwlist, &cafile, &capath, &cadata))
        return NULL;
    if (cafile == Py_None)
        cafile = NULL;
    if (capath == Py_None)
        capath = NULL;
    if (cadata == Py_None)
        cadata = NULL;
    if (cafile == NULL && capath == NULL && cadata == NULL) {
        PyErr_SetString(PyExc_TypeError,
                        "cafile, capath and cadata cannot be all omitted");
        return NULL;
    }
    if (cafile != NULL && !PyString_Check(cafile)) {
        PyErr_SetString(PyExc_TypeError, "cafile should be a valid "
                        "filesystem path");
        return NULL;
    }
    if (cadata != NULL && !PyString_Check(cadata)) {
        PyErr_SetString(PyExc_TypeError,
                        "cadata should be an ASCII string of PEM "
                        "certificates");
        return NULL;
    }
    if (capath != NULL) {
        PyErr_SetString(PyExc_NotImplementedError,
                        "OpenTLS has no capath loader: put PEM files in "
                        "ENVARC:OpenTLS/certs/ or pass cafile");
        return NULL;
    }
    /* Remembered for a rebuilt context, and added now to a built one. */
    if (cafile != NULL) {
        if (ctx_remember(&self->cafiles, cafile) < 0)
            return NULL;
        if (self->ctx != NULL
            && ctx_add_file(self, PyString_AsString(cafile), 0) < 0)
            return NULL;
    }
    if (cadata != NULL) {
        if (ctx_remember(&self->cadata, cadata) < 0)
            return NULL;
        if (self->ctx != NULL && ctx_add_pem(self, cadata) < 0)
            return NULL;
    }
    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject *
load_dh_params(PySSLContext *self, PyObject *filepath)
{
    (void)self;
    (void)filepath;
    PyErr_SetString(PyExc_NotImplementedError,
                    "load_dh_params is for servers; OpenTLS is a client");
    return NULL;
}

static PyObject *
context_wrap_socket(PySSLContext *self, PyObject *args, PyObject *kwds)
{
    char *kwlist[5];
    PySocketSockObject *sock;
    int server_side;
    PyObject *hostname_obj;
    PyObject *ssl_sock;
    char *hostname;

    kwlist[0] = "sock";
    kwlist[1] = "server_side";
    kwlist[2] = "server_hostname";
    kwlist[3] = "ssl_sock";
    kwlist[4] = NULL;
    server_side = 0;
    hostname_obj = Py_None;
    ssl_sock = Py_None;
    hostname = NULL;
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O!i|OO:_wrap_socket",
                                     kwlist,
                                     PySocketModule.Sock_Type, &sock,
                                     &server_side, &hostname_obj, &ssl_sock))
        return NULL;
    if (hostname_obj != NULL && hostname_obj != Py_None) {
        if (!PyString_Check(hostname_obj)) {
            PyErr_SetString(PyExc_TypeError,
                            "server_hostname must be a string or None");
            return NULL;
        }
        hostname = PyString_AsString(hostname_obj);
        if (PyString_Size(hostname_obj) >= 256) {
            PyErr_SetString(PyExc_ValueError, "server_hostname is too long");
            return NULL;
        }
    }
    return (PyObject *)newPySSLSocket(self, sock,
                                      server_side ? PY_SSL_SERVER
                                                  : PY_SSL_CLIENT,
                                      hostname);
}

static PyObject *
session_stats(PySSLContext *self, PyObject *unused)
{
    (void)self;
    (void)unused;
    return Py_BuildValue("{s:i,s:i,s:i,s:i,s:i,s:i,s:i,s:i,s:i,s:i,s:i}",
                         "number", 0,
                         "connect", 0,
                         "connect_good", 0,
                         "connect_renegotiate", 0,
                         "accept", 0,
                         "accept_good", 0,
                         "accept_renegotiate", 0,
                         "hits", 0,
                         "misses", 0,
                         "timeouts", 0,
                         "cache_full", 0);
}

static PyObject *
set_default_verify_paths(PySSLContext *self, PyObject *unused)
{
    (void)unused;
    if (!self->system_trust) {
        self->system_trust = 1;
        if (self->ctx != NULL) {
            if (self->live == 0)
                self->dirty = 1;        /* remade at the next wrap */
            else if (ctx_add_system_trust(self) < 0)
                return NULL;
        }
    }
    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject *
set_ecdh_curve(PySSLContext *self, PyObject *name)
{
    (void)self;
    if (!PyString_Check(name)) {
        PyErr_SetString(PyExc_TypeError, "curve name must be a string");
        return NULL;
    }
    /* OpenTLS offers X25519 and the NIST curves itself. */
    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject *
set_servername_callback(PySSLContext *self, PyObject *args)
{
    (void)self;
    (void)args;
    PyErr_SetString(PyExc_NotImplementedError,
                    "set_servername_callback is for servers; OpenTLS is a "
                    "client");
    return NULL;
}

static PyObject *
cert_store_stats(PySSLContext *self)
{
    return Py_BuildValue("{s:i,s:i,s:i}",
                         "x509", (int)self->trust_count,
                         "crl", 0,
                         "x509_ca", (int)self->trust_count);
}

static PyObject *
get_ca_certs(PySSLContext *self, PyObject *args, PyObject *kwds)
{
    (void)self;
    (void)args;
    (void)kwds;
    /* OpenTLS keeps its trust store to itself. */
    return PyList_New(0);
}

static PyGetSetDef context_getsetlist[] = {
    {"check_hostname", (getter)get_check_hostname,
     (setter)set_check_hostname, NULL},
    {"options", (getter)get_options, (setter)set_options, NULL},
    {"verify_flags", (getter)get_verify_flags, (setter)set_verify_flags, NULL},
    {"verify_mode", (getter)get_verify_mode, (setter)set_verify_mode, NULL},
    {NULL, NULL, NULL, NULL}
};

static struct PyMethodDef context_methods[] = {
    {"_wrap_socket", (PyCFunction)context_wrap_socket,
     METH_VARARGS | METH_KEYWORDS, NULL},
    {"set_ciphers", (PyCFunction)set_ciphers, METH_VARARGS, NULL},
    {"_set_alpn_protocols", (PyCFunction)_set_alpn_protocols,
     METH_VARARGS, NULL},
    {"_set_npn_protocols", (PyCFunction)_set_npn_protocols,
     METH_VARARGS, NULL},
    {"load_cert_chain", (PyCFunction)load_cert_chain,
     METH_VARARGS | METH_KEYWORDS, NULL},
    {"load_dh_params", (PyCFunction)load_dh_params, METH_O, NULL},
    {"load_verify_locations", (PyCFunction)load_verify_locations,
     METH_VARARGS | METH_KEYWORDS, NULL},
    {"session_stats", (PyCFunction)session_stats, METH_NOARGS, NULL},
    {"set_default_verify_paths", (PyCFunction)set_default_verify_paths,
     METH_NOARGS, NULL},
    {"set_ecdh_curve", (PyCFunction)set_ecdh_curve, METH_O, NULL},
    {"set_servername_callback", (PyCFunction)set_servername_callback,
     METH_VARARGS, NULL},
    {"cert_store_stats", (PyCFunction)cert_store_stats, METH_NOARGS, NULL},
    {"get_ca_certs", (PyCFunction)get_ca_certs,
     METH_VARARGS | METH_KEYWORDS, NULL},
    {NULL, NULL, 0, NULL}
};

static PyTypeObject PySSLContext_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "_ssl._SSLContext",                 /* tp_name */
    sizeof(PySSLContext),               /* tp_basicsize */
    0,                                  /* tp_itemsize */
    (destructor)context_dealloc,        /* tp_dealloc */
    0,                                  /* tp_print */
    0,                                  /* tp_getattr */
    0,                                  /* tp_setattr */
    0,                                  /* tp_compare */
    0,                                  /* tp_repr */
    0,                                  /* tp_as_number */
    0,                                  /* tp_as_sequence */
    0,                                  /* tp_as_mapping */
    0,                                  /* tp_hash */
    0,                                  /* tp_call */
    0,                                  /* tp_str */
    PyObject_GenericGetAttr,            /* tp_getattro */
    0,                                  /* tp_setattro */
    0,                                  /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /* tp_flags */
    0,                                  /* tp_doc */
    0,                                  /* tp_traverse */
    0,                                  /* tp_clear */
    0,                                  /* tp_richcompare */
    0,                                  /* tp_weaklistoffset */
    0,                                  /* tp_iter */
    0,                                  /* tp_iternext */
    context_methods,                    /* tp_methods */
    0,                                  /* tp_members */
    context_getsetlist,                 /* tp_getset */
    0,                                  /* tp_base */
    0,                                  /* tp_dict */
    0,                                  /* tp_descr_get */
    0,                                  /* tp_descr_set */
    0,                                  /* tp_dictoffset */
    0,                                  /* tp_init */
    PyType_GenericAlloc,                /* tp_alloc */
    context_new,                        /* tp_new */
    PyObject_Del                        /* tp_free */
};

/* ------------------------------------------------------------------ */
/* Module functions */

static PyObject *
asn1obj2py(const pyssl_asn1_obj *obj)
{
    return Py_BuildValue("isss", obj->nid, obj->sn, obj->ln, obj->oid);
}

static PyObject *
PySSL_txt2obj(PyObject *self, PyObject *args, PyObject *kwds)
{
    char *kwlist[3];
    char *txt;
    PyObject *pyname;
    int name;
    const pyssl_asn1_obj *p;

    (void)self;
    kwlist[0] = "txt";
    kwlist[1] = "name";
    kwlist[2] = NULL;
    pyname = Py_False;
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "s|O:txt2obj", kwlist,
                                     &txt, &pyname))
        return NULL;
    name = PyObject_IsTrue(pyname);
    if (name < 0)
        return NULL;
    for (p = pyssl_asn1_table; p->oid != NULL; p++) {
        if (name) {
            if (strcmp(txt, p->sn) == 0 || strcmp(txt, p->ln) == 0)
                return asn1obj2py(p);
        } else if (strcmp(txt, p->oid) == 0) {
            return asn1obj2py(p);
        }
    }
    PyErr_Format(PyExc_ValueError, "unknown object '%.100s'", txt);
    return NULL;
}

static PyObject *
PySSL_nid2obj(PyObject *self, PyObject *args)
{
    int nid;
    const pyssl_asn1_obj *p;

    (void)self;
    if (!PyArg_ParseTuple(args, "i:nid2obj", &nid))
        return NULL;
    if (nid < 0) {
        PyErr_SetString(PyExc_ValueError, "NID must be positive.");
        return NULL;
    }
    for (p = pyssl_asn1_table; p->oid != NULL; p++) {
        if (p->nid == nid)
            return asn1obj2py(p);
    }
    PyErr_Format(PyExc_ValueError, "unknown NID %i", nid);
    return NULL;
}

static PyObject *
PySSL_RAND_status(PyObject *self)
{
    (void)self;
    return PyInt_FromLong(1);
}

static PyObject *
PySSL_RAND_add(PyObject *self, PyObject *args)
{
    char *buf;
    int len;
    PyObject *entropy;

    (void)self;
    if (!PyArg_ParseTuple(args, "s#O:RAND_add", &buf, &len, &entropy))
        return NULL;
    /* OpenTLS seeds itself (OT_Random). */
    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject *
PySSL_get_default_verify_paths(PyObject *self)
{
    (void)self;
    return Py_BuildValue("(ssss)",
                         "SSL_CERT_FILE", pyssl_ca_bundle,
                         "SSL_CERT_DIR", pyssl_ca_dir);
}

static PyMethodDef PySSL_methods[] = {
    {"RAND_add", PySSL_RAND_add, METH_VARARGS, NULL},
    {"RAND_status", (PyCFunction)PySSL_RAND_status, METH_NOARGS, NULL},
    {"get_default_verify_paths", (PyCFunction)PySSL_get_default_verify_paths,
     METH_NOARGS, NULL},
    {"txt2obj", (PyCFunction)PySSL_txt2obj, METH_VARARGS | METH_KEYWORDS, NULL},
    {"nid2obj", (PyCFunction)PySSL_nid2obj, METH_VARARGS, NULL},
    {NULL, NULL, 0, NULL}
};

static int
add_flag(PyObject *m, const char *name, int on)
{
    PyObject *r;

    r = on ? Py_True : Py_False;
    Py_INCREF(r);
    return PyModule_AddObject(m, name, r);
}

PyDoc_STRVAR(module_doc,
"Implementation module for SSL socket operations, OpenTLS backend "
"(opentls.library).");

void
init_ssl(void)
{
    PyObject *m;
    PyObject *oi;
    char verbuf[64];
    int libver;
    int librev;

    if (opentls_open() != 0)
        return;

    Py_TYPE(&PySSLContext_Type) = &PyType_Type;
    Py_TYPE(&PySSLSocket_Type) = &PyType_Type;
    PySSLContext_Type.tp_new = context_new;
    PySSLContext_Type.tp_alloc = PyType_GenericAlloc;
    PySSLContext_Type.tp_free = PyObject_Del;
    PySSLSocket_Type.tp_alloc = PyType_GenericAlloc;
    PySSLSocket_Type.tp_free = PyObject_Del;
    if (PyType_Ready(&PySSLContext_Type) < 0)
        return;
    if (PyType_Ready(&PySSLSocket_Type) < 0)
        return;

    m = Py_InitModule3("_ssl", PySSL_methods, module_doc);
    if (m == NULL)
        return;

    if (PySocketModule_ImportModuleAndAPI())
        return;

    PySSLErrorObject = PyErr_NewException("ssl.SSLError",
                                          PySocketModule.error, NULL);
    PySSLZeroReturnErrorObject = PyErr_NewException("ssl.SSLZeroReturnError",
                                                    PySSLErrorObject, NULL);
    PySSLWantReadErrorObject = PyErr_NewException("ssl.SSLWantReadError",
                                                  PySSLErrorObject, NULL);
    PySSLWantWriteErrorObject = PyErr_NewException("ssl.SSLWantWriteError",
                                                   PySSLErrorObject, NULL);
    PySSLSyscallErrorObject = PyErr_NewException("ssl.SSLSyscallError",
                                                 PySSLErrorObject, NULL);
    PySSLEOFErrorObject = PyErr_NewException("ssl.SSLEOFError",
                                             PySSLErrorObject, NULL);
    if (PySSLErrorObject == NULL || PySSLZeroReturnErrorObject == NULL
        || PySSLWantReadErrorObject == NULL || PySSLWantWriteErrorObject == NULL
        || PySSLSyscallErrorObject == NULL || PySSLEOFErrorObject == NULL)
        return;

    Py_INCREF(PySSLErrorObject);
    PyModule_AddObject(m, "SSLError", PySSLErrorObject);
    Py_INCREF(PySSLZeroReturnErrorObject);
    PyModule_AddObject(m, "SSLZeroReturnError", PySSLZeroReturnErrorObject);
    Py_INCREF(PySSLWantReadErrorObject);
    PyModule_AddObject(m, "SSLWantReadError", PySSLWantReadErrorObject);
    Py_INCREF(PySSLWantWriteErrorObject);
    PyModule_AddObject(m, "SSLWantWriteError", PySSLWantWriteErrorObject);
    Py_INCREF(PySSLSyscallErrorObject);
    PyModule_AddObject(m, "SSLSyscallError", PySSLSyscallErrorObject);
    Py_INCREF(PySSLEOFErrorObject);
    PyModule_AddObject(m, "SSLEOFError", PySSLEOFErrorObject);
    Py_INCREF((PyObject *)&PySSLContext_Type);
    PyModule_AddObject(m, "_SSLContext", (PyObject *)&PySSLContext_Type);
    Py_INCREF((PyObject *)&PySSLSocket_Type);
    PyModule_AddObject(m, "_SSLSocket", (PyObject *)&PySSLSocket_Type);

    PyModule_AddIntConstant(m, "SSL_ERROR_ZERO_RETURN", PY_SSL_ERROR_ZERO_RETURN);
    PyModule_AddIntConstant(m, "SSL_ERROR_WANT_READ", PY_SSL_ERROR_WANT_READ);
    PyModule_AddIntConstant(m, "SSL_ERROR_WANT_WRITE", PY_SSL_ERROR_WANT_WRITE);
    PyModule_AddIntConstant(m, "SSL_ERROR_WANT_X509_LOOKUP",
                            PY_SSL_ERROR_WANT_X509_LOOKUP);
    PyModule_AddIntConstant(m, "SSL_ERROR_SYSCALL", PY_SSL_ERROR_SYSCALL);
    PyModule_AddIntConstant(m, "SSL_ERROR_SSL", PY_SSL_ERROR_SSL);
    PyModule_AddIntConstant(m, "SSL_ERROR_WANT_CONNECT",
                            PY_SSL_ERROR_WANT_CONNECT);
    PyModule_AddIntConstant(m, "SSL_ERROR_EOF", PY_SSL_ERROR_EOF);
    PyModule_AddIntConstant(m, "SSL_ERROR_INVALID_ERROR_CODE",
                            PY_SSL_ERROR_INVALID_ERROR_CODE);
    PyModule_AddIntConstant(m, "CERT_NONE", PY_SSL_CERT_NONE);
    PyModule_AddIntConstant(m, "CERT_OPTIONAL", PY_SSL_CERT_OPTIONAL);
    PyModule_AddIntConstant(m, "CERT_REQUIRED", PY_SSL_CERT_REQUIRED);
    PyModule_AddIntConstant(m, "VERIFY_DEFAULT", 0);
    PyModule_AddIntConstant(m, "VERIFY_CRL_CHECK_LEAF", 0x4);
    PyModule_AddIntConstant(m, "VERIFY_CRL_CHECK_CHAIN", 0x8);
    PyModule_AddIntConstant(m, "VERIFY_X509_STRICT", 0x20);
    PyModule_AddIntConstant(m, "PROTOCOL_TLS", PY_SSL_VERSION_TLS);
    PyModule_AddIntConstant(m, "PROTOCOL_SSLv23", PY_SSL_VERSION_TLS);
    PyModule_AddIntConstant(m, "PROTOCOL_TLSv1", PY_SSL_VERSION_TLS1);
    PyModule_AddIntConstant(m, "PROTOCOL_TLSv1_1", PY_SSL_VERSION_TLS1_1);
    PyModule_AddIntConstant(m, "PROTOCOL_TLSv1_2", PY_SSL_VERSION_TLS1_2);

    PyModule_AddIntConstant(m, "OP_ALL",
                            (long)(PYSSL_OP_ALL &
                                   ~PYSSL_OP_DONT_INSERT_EMPTY_FRAGMENTS));
    PyModule_AddIntConstant(m, "OP_NO_SSLv2", 0);
    PyModule_AddIntConstant(m, "OP_NO_SSLv3", (long)PYSSL_OP_NO_SSLv3);
    PyModule_AddIntConstant(m, "OP_NO_TLSv1", (long)PYSSL_OP_NO_TLSv1);
    PyModule_AddIntConstant(m, "OP_NO_TLSv1_1", (long)PYSSL_OP_NO_TLSv1_1);
    PyModule_AddIntConstant(m, "OP_NO_TLSv1_2", (long)PYSSL_OP_NO_TLSv1_2);
    PyModule_AddIntConstant(m, "OP_NO_TLSv1_3", (long)PYSSL_OP_NO_TLSv1_3);
    PyModule_AddIntConstant(m, "OP_CIPHER_SERVER_PREFERENCE",
                            (long)PYSSL_OP_CIPHER_SERVER_PREFERENCE);
    PyModule_AddIntConstant(m, "OP_SINGLE_DH_USE", 0);
    PyModule_AddIntConstant(m, "OP_SINGLE_ECDH_USE", 0);
    PyModule_AddIntConstant(m, "OP_NO_COMPRESSION",
                            (long)PYSSL_OP_NO_COMPRESSION);
    PyModule_AddIntConstant(m, "OP_ENABLE_MIDDLEBOX_COMPAT",
                            (long)PYSSL_OP_ENABLE_MIDDLEBOX_COMPAT);

    add_flag(m, "HAS_SNI", 1);
    add_flag(m, "HAS_ECDH", 1);
    add_flag(m, "HAS_NPN", 0);
    add_flag(m, "HAS_ALPN", 1);
    /* OpenTLS API version 1 speaks TLS 1.2; 1.3 arrives through the same
     * calls, so this follows the library rather than the module. */
    add_flag(m, "HAS_TLSv1_3", 0);
    add_flag(m, "HAS_TLS_UNIQUE", 0);

    libver = (int)OpenTLSBase->lib_Version;
    librev = (int)OpenTLSBase->lib_Revision;
    /* Compatibility stamp for ssl.py; OPENSSL_VERSION names the library. */
    PyModule_AddIntConstant(m, "OPENSSL_VERSION_NUMBER", 0x1000200FL);
    oi = Py_BuildValue("iiiii", 1, 0, 2, 0, 15);
    if (oi != NULL)
        PyModule_AddObject(m, "OPENSSL_VERSION_INFO", oi);
    PyOS_snprintf(verbuf, sizeof(verbuf), "opentls.library %d.%d (BearSSL)",
                  libver, librev);
    PyModule_AddStringConstant(m, "OPENSSL_VERSION", verbuf);
    if (oi != NULL) {
        Py_INCREF(oi);
        PyModule_AddObject(m, "_OPENSSL_API_VERSION", oi);
    }
    PyModule_AddStringConstant(m, "amiga_tls_backend", "opentls");
    PyModule_AddIntConstant(m, "amiga_plugin_rev", 14);
    PyModule_AddIntConstant(m, "opentls_lib_version", libver);
    PyModule_AddIntConstant(m, "opentls_lib_revision", librev);
    /* OTACC_* bits: which maths AmigaChrome's x86 or ARM64 cores do;
     * 0 on a real Amiga. */
    PyModule_AddIntConstant(m, "opentls_accelerated",
                            (long)OT_Accelerated());
}
