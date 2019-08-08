#define PYCURL_SINGLE_FILE
#if (defined(_WIN32) || defined(__WIN32__)) && !defined(WIN32)
#  define WIN32 1
#endif
#include <Python.h>
#include <pythread.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <sys/types.h>

#if !defined(WIN32)
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/un.h>
#endif

#if defined(WIN32)
/*
 * Since setup.py uses a '-WX' in the CFLAGS (treat warnings as errors),
 * the below will turn off some warnings when using MS-SDK 8.1+.
 * This MUST be defined before including <winsock2.h> via the libcurl
 * headers.
 */
# if !defined(_WINSOCK_DEPRECATED_NO_WARNINGS)
#  define _WINSOCK_DEPRECATED_NO_WARNINGS
# endif
#endif

#include "curl.h"

#include "easy.h"

#include multi.h"

#undef NDEBUG
#include <assert.h>

#define MAKE_LIBCURL_VERSION(major, minor, patch) \
    ((major) * 0x10000 + (minor) * 0x100 + (patch))

/* spot check */
#if MAKE_LIBCURL_VERSION(7, 21, 16) != 0x071510
# error MAKE_LIBCURL_VERSION is not working correctly
#endif

#if defined(PYCURL_SINGLE_FILE)
# define PYCURL_INTERNAL static
#else
# define PYCURL_INTERNAL
#endif

#if defined(WIN32)
/* supposedly not present in errno.h provided with VC */
# if !defined(EAFNOSUPPORT)
#  define EAFNOSUPPORT 97
# endif

PYCURL_INTERNAL int
dup_winsock(int sock, const struct curl_sockaddr *address);
#endif

/* The inet_ntop() was added in ws2_32.dll on Windows Vista [1]. Hence the
 * Windows SDK targeting lesser OS'es doesn't provide that prototype.
 * Maybe we should use the local hidden inet_ntop() for all OS'es thus
 * making a pycurl.pyd work across OS'es w/o rebuilding?
 *
 * [1] http://msdn.microsoft.com/en-us/library/windows/desktop/cc805843(v=vs.85).aspx
 */
#if defined(WIN32) && ((_WIN32_WINNT < 0x0600) || (NTDDI_VERSION < NTDDI_VISTA))
PYCURL_INTERNAL const char *
pycurl_inet_ntop (int family, void *addr, char *string, size_t string_size);
#define inet_ntop(fam,addr,string,size) pycurl_inet_ntop(fam,addr,string,size)
#endif

#if !defined(LIBCURL_VERSION_NUM) || (LIBCURL_VERSION_NUM < 0x071300)
#  error "Need libcurl version 7.19.0 or greater to compile pycurl."
#endif

#if LIBCURL_VERSION_NUM >= 0x071301 /* check for 7.19.1 or greater */
#define HAVE_CURLOPT_USERNAME
#define HAVE_CURLOPT_PROXYUSERNAME
#define HAVE_CURLOPT_CERTINFO
#define HAVE_CURLOPT_POSTREDIR
#endif

#if LIBCURL_VERSION_NUM >= 0x071303 /* check for 7.19.3 or greater */
#define HAVE_CURLAUTH_DIGEST_IE
#endif

#if LIBCURL_VERSION_NUM >= 0x071304 /* check for 7.19.4 or greater */
#define HAVE_CURLOPT_NOPROXY
#define HAVE_CURLOPT_PROTOCOLS
#define HAVE_CURL_7_19_4_OPTS
#endif

#if LIBCURL_VERSION_NUM >= 0x071305 /* check for 7.19.5 or greater */
#define HAVE_CURL_7_19_5_OPTS
#endif

#if LIBCURL_VERSION_NUM >= 0x071306 /* check for 7.19.6 or greater */
#define HAVE_CURL_7_19_6_OPTS
#endif

#if LIBCURL_VERSION_NUM >= 0x071400 /* check for 7.20.0 or greater */
#define HAVE_CURL_7_20_0_OPTS
#endif

#if LIBCURL_VERSION_NUM >= 0x071500 /* check for 7.21.0 or greater */
#define HAVE_CURLINFO_LOCAL_PORT
#define HAVE_CURLINFO_PRIMARY_PORT
#define HAVE_CURLINFO_LOCAL_IP
#define HAVE_CURL_7_21_0_OPTS
#endif

#if LIBCURL_VERSION_NUM >= 0x071502 /* check for 7.21.2 or greater */
#define HAVE_CURL_7_21_2_OPTS
#endif

#if LIBCURL_VERSION_NUM >= 0x071503 /* check for 7.21.3 or greater */
#define HAVE_CURLOPT_RESOLVE
#endif

#if LIBCURL_VERSION_NUM >= 0x071505 /* check for 7.21.5 or greater */
#define HAVE_CURL_7_21_5
#endif

#if LIBCURL_VERSION_NUM >= 0x071600 /* check for 7.22.0 or greater */
#define HAVE_CURL_7_22_0_OPTS
#endif

#if LIBCURL_VERSION_NUM >= 0x071800 /* check for 7.24.0 or greater */
#define HAVE_CURLOPT_DNS_SERVERS
#define HAVE_CURL_7_24_0
#endif

#if LIBCURL_VERSION_NUM >= 0x071900 /* check for 7.25.0 or greater */
#define HAVE_CURL_7_25_0_OPTS
#endif

#if LIBCURL_VERSION_NUM >= 0x071A00 /* check for 7.26.0 or greater */
#define HAVE_CURL_REDIR_POST_303
#endif

#if LIBCURL_VERSION_NUM >= 0x071E00 /* check for 7.30.0 or greater */
#define HAVE_CURL_7_30_0_PIPELINE_OPTS
#endif

#if LIBCURL_VERSION_NUM >= 0x073100 /* check for 7.49.0 or greater */
#define HAVE_CURLOPT_CONNECT_TO
#endif

#if LIBCURL_VERSION_NUM >= 0x073200 /* check for 7.50.0 or greater */
#define HAVE_CURLINFO_HTTP_VERSION
#endif

#undef UNUSED
#define UNUSED(var)     ((void)&var)

/* Cruft for thread safe SSL crypto locks, snapped from the PHP curl extension */
#if defined(HAVE_CURL_SSL)
# if defined(HAVE_CURL_OPENSSL)
#   define PYCURL_NEED_SSL_TSL
#   define PYCURL_NEED_OPENSSL_TSL
#   include <openssl/ssl.h>
#   include <openssl/err.h>
#   define COMPILE_SSL_LIB "openssl"
# elif defined(HAVE_CURL_WOLFSSL)
#   include <wolfssl/options.h>
#   if defined(OPENSSL_EXTRA)
#     define HAVE_CURL_OPENSSL
#     define PYCURL_NEED_SSL_TSL
#     define PYCURL_NEED_OPENSSL_TSL
#     include <wolfssl/openssl/ssl.h>
#     include <wolfssl/openssl/err.h>
#   else
#    ifdef _MSC_VER
#     pragma message(\
       "libcurl was compiled with wolfSSL, but the library was built without " \
       "--enable-opensslextra; thus no SSL crypto locking callbacks will be set, " \
       "which may cause random crashes on SSL requests")
#    else
#     warning \
       "libcurl was compiled with wolfSSL, but the library was built without " \
       "--enable-opensslextra; thus no SSL crypto locking callbacks will be set, " \
       "which may cause random crashes on SSL requests"
#    endif
#   endif
#   define COMPILE_SSL_LIB "wolfssl"
# elif defined(HAVE_CURL_GNUTLS)
#   include <gnutls/gnutls.h>
#   if GNUTLS_VERSION_NUMBER <= 0x020b00
#     define PYCURL_NEED_SSL_TSL
#     define PYCURL_NEED_GNUTLS_TSL
#     include <gcrypt.h>
#   endif
#   define COMPILE_SSL_LIB "gnutls"
# elif defined(HAVE_CURL_NSS)
#   define COMPILE_SSL_LIB "nss"
# elif defined(HAVE_CURL_MBEDTLS)
#   include <mbedtls/ssl.h>
#   define PYCURL_NEED_SSL_TSL
#   define PYCURL_NEED_MBEDTLS_TSL
#   define COMPILE_SSL_LIB "mbedtls"
# else
#  ifdef _MSC_VER
    /* sigh */
#   pragma message(\
     "libcurl was compiled with SSL support, but configure could not determine which " \
     "library was used; thus no SSL crypto locking callbacks will be set, which may " \
     "cause random crashes on SSL requests")
#  else
#   warning \
     "libcurl was compiled with SSL support, but configure could not determine which " \
     "library was used; thus no SSL crypto locking callbacks will be set, which may " \
     "cause random crashes on SSL requests"
#  endif
   /* since we have no crypto callbacks for other ssl backends,
    * no reason to require users match those */
#  define COMPILE_SSL_LIB "none/other"
# endif /* HAVE_CURL_OPENSSL || HAVE_CURL_WOLFSSL || HAVE_CURL_GNUTLS || HAVE_CURL_NSS || HAVE_CURL_MBEDTLS */
#else
# define COMPILE_SSL_LIB "none/other"
#endif /* HAVE_CURL_SSL */

#if defined(PYCURL_NEED_SSL_TSL)
PYCURL_INTERNAL int pycurl_ssl_init(void);
PYCURL_INTERNAL void pycurl_ssl_cleanup(void);
#endif

#ifdef WITH_THREAD
#  define PYCURL_DECLARE_THREAD_STATE PyThreadState *tmp_state
#  define PYCURL_ACQUIRE_THREAD() pycurl_acquire_thread(self, &tmp_state)
#  define PYCURL_ACQUIRE_THREAD_MULTI() pycurl_acquire_thread_multi(self, &tmp_state)
#  define PYCURL_RELEASE_THREAD() pycurl_release_thread(tmp_state)
/* Replacement for Py_BEGIN_ALLOW_THREADS/Py_END_ALLOW_THREADS when python
   callbacks are expected during blocking i/o operations: self->state will hold
   the handle to current thread to be used as context */
#  define PYCURL_BEGIN_ALLOW_THREADS \
       self->state = PyThreadState_Get(); \
       assert(self->state != NULL); \
       Py_BEGIN_ALLOW_THREADS
#  define PYCURL_END_ALLOW_THREADS \
       Py_END_ALLOW_THREADS \
       self->state = NULL;
#else
#  define PYCURL_DECLARE_THREAD_STATE
#  define PYCURL_ACQUIRE_THREAD() (1)
#  define PYCURL_ACQUIRE_THREAD_MULTI() (1)
#  define PYCURL_RELEASE_THREAD()
#  define PYCURL_BEGIN_ALLOW_THREADS
#  define PYCURL_END_ALLOW_THREADS
#endif

#if PY_MAJOR_VERSION >= 3
  #define PyInt_Type                   PyLong_Type
  #define PyInt_Check(op)              PyLong_Check(op)
  #define PyInt_FromLong               PyLong_FromLong
  #define PyInt_AsLong                 PyLong_AsLong
#endif

#define PYLISTORTUPLE_LIST 1
#define PYLISTORTUPLE_TUPLE 2
#define PYLISTORTUPLE_OTHER 0

PYCURL_INTERNAL int
PyListOrTuple_Check(PyObject *v);
PYCURL_INTERNAL Py_ssize_t
PyListOrTuple_Size(PyObject *v, int which);
PYCURL_INTERNAL PyObject *
PyListOrTuple_GetItem(PyObject *v, Py_ssize_t i, int which);

/*************************************************************************
// python 2/3 compatibility
**************************************************************************/

#if PY_MAJOR_VERSION >= 3
# define PyText_FromFormat(format, str) PyUnicode_FromFormat((format), (str))
# define PyText_FromString(str) PyUnicode_FromString(str)
# define PyByteStr_FromString(str) PyBytes_FromString(str)
# define PyByteStr_Check(obj) PyBytes_Check(obj)
# define PyByteStr_AsStringAndSize(obj, buffer, length) PyBytes_AsStringAndSize((obj), (buffer), (length))
#else
# define PyText_FromFormat(format, str) PyString_FromFormat((format), (str))
# define PyText_FromString(str) PyString_FromString(str)
# define PyByteStr_FromString(str) PyString_FromString(str)
# define PyByteStr_Check(obj) PyString_Check(obj)
# define PyByteStr_AsStringAndSize(obj, buffer, length) PyString_AsStringAndSize((obj), (buffer), (length))
#endif
#define PyText_EncodedDecref(encoded) Py_XDECREF(encoded)

PYCURL_INTERNAL int
PyText_AsStringAndSize(PyObject *obj, char **buffer, Py_ssize_t *length, PyObject **encoded_obj);
PYCURL_INTERNAL char *
PyText_AsString_NoNUL(PyObject *obj, PyObject **encoded_obj);
PYCURL_INTERNAL int
PyText_Check(PyObject *o);
PYCURL_INTERNAL PyObject *
PyText_FromString_Ignore(const char *string);

struct CurlObject;

PYCURL_INTERNAL void
create_and_set_error_object(struct CurlObject *self, int code);


/* Raise exception based on return value `res' and `self->error' */
#define CURLERROR_RETVAL() do {\
    create_and_set_error_object((self), (int) (res)); \
    return NULL; \
} while (0)

#define CURLERROR_SET_RETVAL() \
    create_and_set_error_object((self), (int) (res));

#define CURLERROR_RETVAL_MULTI_DONE() do {\
    PyObject *v; \
    v = Py_BuildValue("(i)", (int) (res)); \
    if (v != NULL) { PyErr_SetObject(ErrorObject, v); Py_DECREF(v); } \
    goto done; \
} while (0)

/* Raise exception based on return value `res' and custom message */
/* msg should be ASCII */
#define CURLERROR_MSG(msg) do {\
    PyObject *v; const char *m = (msg); \
    v = Py_BuildValue("(is)", (int) (res), (m)); \
    if (v != NULL) { PyErr_SetObject(ErrorObject, v); Py_DECREF(v); } \
    return NULL; \
} while (0)


/* Calculate the number of OBJECTPOINT options we need to store */
#define OPTIONS_SIZE    ((int)CURLOPT_LASTENTRY % 10000)
#define MOPTIONS_SIZE   ((int)CURLMOPT_LASTENTRY % 10000)

/* Memory groups */
/* Attributes dictionary */
#define PYCURL_MEMGROUP_ATTRDICT        1
/* multi_stack */
#define PYCURL_MEMGROUP_MULTI           2
/* Python callbacks */
#define PYCURL_MEMGROUP_CALLBACK        4
/* Python file objects */
#define PYCURL_MEMGROUP_FILE            8
/* Share objects */
#define PYCURL_MEMGROUP_SHARE           16
/* httppost buffer references */
#define PYCURL_MEMGROUP_HTTPPOST        32
/* Postfields object */
#define PYCURL_MEMGROUP_POSTFIELDS      64
/* CA certs object */
#define PYCURL_MEMGROUP_CACERTS         128

#define PYCURL_MEMGROUP_EASY \
    (PYCURL_MEMGROUP_CALLBACK | PYCURL_MEMGROUP_FILE | \
    PYCURL_MEMGROUP_HTTPPOST | PYCURL_MEMGROUP_POSTFIELDS | \
    PYCURL_MEMGROUP_CACERTS)

#define PYCURL_MEMGROUP_ALL \
    (PYCURL_MEMGROUP_ATTRDICT | PYCURL_MEMGROUP_EASY | \
    PYCURL_MEMGROUP_MULTI | PYCURL_MEMGROUP_SHARE)

typedef struct CurlObject {
    PyObject_HEAD
    PyObject *dict;                 /* Python attributes dictionary */
    // https://docs.python.org/3/extending/newtypes.html
    PyObject *weakreflist;
    CURL *handle;
#ifdef WITH_THREAD
    PyThreadState *state;
#endif
    struct CurlMultiObject *multi_stack;
    struct CurlShareObject *share;
    struct curl_httppost *httppost;
    /* List of INC'ed references associated with httppost. */
    PyObject *httppost_ref_list;
    struct curl_slist *httpheader;
#if LIBCURL_VERSION_NUM >= MAKE_LIBCURL_VERSION(7, 37, 0)
    struct curl_slist *proxyheader;
#endif
    struct curl_slist *http200aliases;
    struct curl_slist *quote;
    struct curl_slist *postquote;
    struct curl_slist *prequote;
    struct curl_slist *telnetoptions;
#ifdef HAVE_CURLOPT_RESOLVE
    struct curl_slist *resolve;
#endif
#ifdef HAVE_CURL_7_20_0_OPTS
    struct curl_slist *mail_rcpt;
#endif
#ifdef HAVE_CURLOPT_CONNECT_TO
    struct curl_slist *connect_to;
#endif
    /* callbacks */
    PyObject *w_cb;
    PyObject *h_cb;
    PyObject *r_cb;
    PyObject *pro_cb;
#if LIBCURL_VERSION_NUM >= MAKE_LIBCURL_VERSION(7, 32, 0)
    PyObject *xferinfo_cb;
#endif
    PyObject *debug_cb;
    PyObject *ioctl_cb;
    PyObject *opensocket_cb;
#if LIBCURL_VERSION_NUM >= 0x071507 /* check for 7.21.7 or greater */
    PyObject *closesocket_cb;
#endif
    PyObject *seek_cb;
    PyObject *sockopt_cb;
    PyObject *ssh_key_cb;
    /* file objects */
    PyObject *readdata_fp;
    PyObject *writedata_fp;
    PyObject *writeheader_fp;
    /* reference to the object used for CURLOPT_POSTFIELDS */
    PyObject *postfields_obj;
    /* reference to the object containing ca certs */
    PyObject *ca_certs_obj;
    /* misc */
    char error[CURL_ERROR_SIZE+1];
} CurlObject;

typedef struct CurlMultiObject {
    PyObject_HEAD
    PyObject *dict;                 /* Python attributes dictionary */
    // https://docs.python.org/3/extending/newtypes.html
    PyObject *weakreflist;
    CURLM *multi_handle;
#ifdef WITH_THREAD
    PyThreadState *state;
#endif
    fd_set read_fd_set;
    fd_set write_fd_set;
    fd_set exc_fd_set;
    /* callbacks */
    PyObject *t_cb;
    PyObject *s_cb;

    PyObject *easy_object_dict;
} CurlMultiObject;

typedef struct {
    PyThread_type_lock locks[CURL_LOCK_DATA_LAST];
} ShareLock;

typedef struct CurlShareObject {
    PyObject_HEAD
    PyObject *dict;                 /* Python attributes dictionary */
    // https://docs.python.org/3/extending/newtypes.html
    PyObject *weakreflist;
    CURLSH *share_handle;
#ifdef WITH_THREAD
    ShareLock *lock;                /* lock object to implement CURLSHOPT_LOCKFUNC */
#endif
} CurlShareObject;

#ifdef WITH_THREAD

PYCURL_INTERNAL PyThreadState *
pycurl_get_thread_state(const CurlObject *self);
PYCURL_INTERNAL PyThreadState *
pycurl_get_thread_state_multi(const CurlMultiObject *self);
PYCURL_INTERNAL int
pycurl_acquire_thread(const CurlObject *self, PyThreadState **state);
PYCURL_INTERNAL int
pycurl_acquire_thread_multi(const CurlMultiObject *self, PyThreadState **state);
PYCURL_INTERNAL void
pycurl_release_thread(PyThreadState *state);

PYCURL_INTERNAL void
share_lock_lock(ShareLock *lock, curl_lock_data data);
PYCURL_INTERNAL void
share_lock_unlock(ShareLock *lock, curl_lock_data data);
PYCURL_INTERNAL ShareLock *
share_lock_new(void);
PYCURL_INTERNAL void
share_lock_destroy(ShareLock *lock);
PYCURL_INTERNAL void
share_lock_callback(CURL *handle, curl_lock_data data, curl_lock_access locktype, void *userptr);
PYCURL_INTERNAL void
share_unlock_callback(CURL *handle, curl_lock_data data, void *userptr);

#endif /* WITH_THREAD */

#if PY_MAJOR_VERSION >= 3
PYCURL_INTERNAL PyObject *
my_getattro(PyObject *co, PyObject *name, PyObject *dict1, PyObject *dict2, PyMethodDef *m);
PYCURL_INTERNAL int
my_setattro(PyObject **dict, PyObject *name, PyObject *v);
#else /* PY_MAJOR_VERSION >= 3 */
PYCURL_INTERNAL int
my_setattr(PyObject **dict, char *name, PyObject *v);
PYCURL_INTERNAL PyObject *
my_getattr(PyObject *co, char *name, PyObject *dict1, PyObject *dict2, PyMethodDef *m);
#endif /* PY_MAJOR_VERSION >= 3 */

/* used by multi object */
PYCURL_INTERNAL void
assert_curl_state(const CurlObject *self);

PYCURL_INTERNAL PyObject *
do_global_init(PyObject *dummy, PyObject *args);
PYCURL_INTERNAL PyObject *
do_global_cleanup(PyObject *dummy);
PYCURL_INTERNAL PyObject *
do_version_info(PyObject *dummy, PyObject *args);

PYCURL_INTERNAL PyObject *
do_curl_setopt(CurlObject *self, PyObject *args);
PYCURL_INTERNAL PyObject *
do_curl_setopt_string(CurlObject *self, PyObject *args);
PYCURL_INTERNAL PyObject *
do_curl_unsetopt(CurlObject *self, PyObject *args);
#if defined(HAVE_CURL_OPENSSL)
PYCURL_INTERNAL PyObject *
do_curl_set_ca_certs(CurlObject *self, PyObject *args);
#endif
PYCURL_INTERNAL PyObject *
do_curl_perform(CurlObject *self);
PYCURL_INTERNAL PyObject *
do_curl_perform_rb(CurlObject *self);
#if PY_MAJOR_VERSION >= 3
PYCURL_INTERNAL PyObject *
do_curl_perform_rs(CurlObject *self);
#else
# define do_curl_perform_rs do_curl_perform_rb
#endif

PYCURL_INTERNAL PyObject *
do_curl_pause(CurlObject *self, PyObject *args);

PYCURL_INTERNAL int
check_curl_state(const CurlObject *self, int flags, const char *name);
PYCURL_INTERNAL void
util_curl_xdecref(CurlObject *self, int flags, CURL *handle);
PYCURL_INTERNAL PyObject *
do_curl_setopt_filelike(CurlObject *self, int option, PyObject *obj);

PYCURL_INTERNAL PyObject *
do_curl_getinfo_raw(CurlObject *self, PyObject *args);
#if PY_MAJOR_VERSION >= 3
PYCURL_INTERNAL PyObject *
do_curl_getinfo(CurlObject *self, PyObject *args);
#else
# define do_curl_getinfo do_curl_getinfo_raw
#endif
PYCURL_INTERNAL PyObject *
do_curl_errstr(CurlObject *self);
#if PY_MAJOR_VERSION >= 3
PYCURL_INTERNAL PyObject *
do_curl_errstr_raw(CurlObject *self);
#else
# define do_curl_errstr_raw do_curl_errstr
#endif

PYCURL_INTERNAL size_t
write_callback(char *ptr, size_t size, size_t nmemb, void *stream);
PYCURL_INTERNAL size_t
header_callback(char *ptr, size_t size, size_t nmemb, void *stream);
PYCURL_INTERNAL curl_socket_t
opensocket_callback(void *clientp, curlsocktype purpose,
                    struct curl_sockaddr *address);
PYCURL_INTERNAL int
sockopt_cb(void *clientp, curl_socket_t curlfd, curlsocktype purpose);
#if LIBCURL_VERSION_NUM >= MAKE_LIBCURL_VERSION(7, 21, 7)
PYCURL_INTERNAL int
closesocket_callback(void *clientp, curl_socket_t curlfd);
#endif
#ifdef HAVE_CURL_7_19_6_OPTS
PYCURL_INTERNAL int
ssh_key_cb(CURL *easy, const struct curl_khkey *knownkey,
    const struct curl_khkey *foundkey, int khmatch, void *clientp);
#endif
PYCURL_INTERNAL int
seek_callback(void *stream, curl_off_t offset, int origin);
PYCURL_INTERNAL size_t
read_callback(char *ptr, size_t size, size_t nmemb, void *stream);
PYCURL_INTERNAL int
progress_callback(void *stream,
                  double dltotal, double dlnow, double ultotal, double ulnow);
#if LIBCURL_VERSION_NUM >= MAKE_LIBCURL_VERSION(7, 32, 0)
PYCURL_INTERNAL int
xferinfo_callback(void *stream,
    curl_off_t dltotal, curl_off_t dlnow,
    curl_off_t ultotal, curl_off_t ulnow);
#endif
PYCURL_INTERNAL int
debug_callback(CURL *curlobj, curl_infotype type,
               char *buffer, size_t total_size, void *stream);
PYCURL_INTERNAL curlioerr
ioctl_callback(CURL *curlobj, int cmd, void *stream);
#if defined(HAVE_CURL_OPENSSL)
PYCURL_INTERNAL CURLcode
ssl_ctx_callback(CURL *curl, void *ssl_ctx, void *ptr);
#endif

#if !defined(PYCURL_SINGLE_FILE)
/* Type objects */
extern PyTypeObject Curl_Type;
extern PyTypeObject CurlMulti_Type;
extern PyTypeObject CurlShare_Type;

extern PyObject *ErrorObject;
extern PyTypeObject *p_Curl_Type;
extern PyTypeObject *p_CurlMulti_Type;
extern PyTypeObject *p_CurlShare_Type;
extern PyObject *khkey_type;
extern PyObject *curl_sockaddr_type;

extern PyObject *curlobject_constants;
extern PyObject *curlmultiobject_constants;
extern PyObject *curlshareobject_constants;

extern char *g_pycurl_useragent;

extern PYCURL_INTERNAL char *empty_keywords[];
extern PYCURL_INTERNAL PyObject *bytesio;
extern PYCURL_INTERNAL PyObject *stringio;

#if PY_MAJOR_VERSION >= 3
extern PyMethodDef curlobject_methods[];
extern PyMethodDef curlshareobject_methods[];
extern PyMethodDef curlmultiobject_methods[];
#endif
#endif /* !PYCURL_SINGLE_FILE */

#if PY_MAJOR_VERSION >= 3
# define PYCURL_TYPE_FLAGS Py_TPFLAGS_HAVE_GC
#else
# define PYCURL_TYPE_FLAGS Py_TPFLAGS_HAVE_GC | Py_TPFLAGS_HAVE_WEAKREFS
#endif

/* vi:ts=4:et:nowrap
 */
/* Generated file - do not edit. */
/* See doc/docstrings/ *.rst. */



PYCURL_INTERNAL const char curl_doc[] = "Curl() -> New Curl object\n\
\n\
Creates a new :ref:`curlobject` which corresponds to a\n\
``CURL`` handle in libcurl. Curl objects automatically set\n\
CURLOPT_VERBOSE to 0, CURLOPT_NOPROGRESS to 1, provide a default\n\
CURLOPT_USERAGENT and setup CURLOPT_ERRORBUFFER to point to a\n\
private error buffer.\n\
\n\
Implicitly calls :py:func:`pycurl.global_init` if the latter has not yet been called.";

PYCURL_INTERNAL const char curl_close_doc[] = "close() -> None\n\
\n\
Close handle and end curl session.\n\
\n\
Corresponds to `curl_easy_cleanup`_ in libcurl. This method is\n\
automatically called by pycurl when a Curl object no longer has any\n\
references to it, but can also be called explicitly.\n\
\n\
.. _curl_easy_cleanup:\n\
    https://curl.haxx.se/libcurl/c/curl_easy_cleanup.html";

PYCURL_INTERNAL const char curl_errstr_doc[] = "errstr() -> string\n\
\n\
Return the internal libcurl error buffer of this handle as a string.\n\
\n\
Return value is a ``str`` instance on all Python versions.\n\
On Python 3, error buffer data is decoded using Python's default encoding\n\
at the time of the call. If this decoding fails, ``UnicodeDecodeError`` is\n\
raised. Use :ref:`errstr_raw <errstr_raw>` to retrieve the error buffer\n\
as a byte string in this case.\n\
\n\
On Python 2, ``errstr`` and ``errstr_raw`` behave identically.";

PYCURL_INTERNAL const char curl_errstr_raw_doc[] = "errstr_raw() -> byte string\n\
\n\
Return the internal libcurl error buffer of this handle as a byte string.\n\
\n\
Return value is a ``str`` instance on Python 2 and ``bytes`` instance\n\
on Python 3. Unlike :ref:`errstr_raw <errstr_raw>`, ``errstr_raw``\n\
allows reading libcurl error buffer in Python 3 when its contents is not\n\
valid in Python's default encoding.\n\
\n\
On Python 2, ``errstr`` and ``errstr_raw`` behave identically.\n\
\n\
*Added in version 7.43.0.2.*";

PYCURL_INTERNAL const char curl_getinfo_doc[] = "getinfo(option) -> Result\n\
\n\
Extract and return information from a curl session,\n\
decoding string data in Python's default encoding at the time of the call.\n\
Corresponds to `curl_easy_getinfo`_ in libcurl.\n\
The ``getinfo`` method should not be called unless\n\
``perform`` has been called and finished.\n\
\n\
*option* is a constant corresponding to one of the\n\
``CURLINFO_*`` constants in libcurl. Most option constant names match\n\
the respective ``CURLINFO_*`` constant names with the ``CURLINFO_`` prefix\n\
removed, for example ``CURLINFO_CONTENT_TYPE`` is accessible as\n\
``pycurl.CONTENT_TYPE``. Exceptions to this rule are as follows:\n\
\n\
- ``CURLINFO_FILETIME`` is mapped as ``pycurl.INFO_FILETIME``\n\
- ``CURLINFO_COOKIELIST`` is mapped as ``pycurl.INFO_COOKIELIST``\n\
- ``CURLINFO_CERTINFO`` is mapped as ``pycurl.INFO_CERTINFO``\n\
- ``CURLINFO_RTSP_CLIENT_CSEQ`` is mapped as ``pycurl.INFO_RTSP_CLIENT_CSEQ``\n\
- ``CURLINFO_RTSP_CSEQ_RECV`` is mapped as ``pycurl.INFO_RTSP_CSEQ_RECV``\n\
- ``CURLINFO_RTSP_SERVER_CSEQ`` is mapped as ``pycurl.INFO_RTSP_SERVER_CSEQ``\n\
- ``CURLINFO_RTSP_SESSION_ID`` is mapped as ``pycurl.INFO_RTSP_SESSION_ID``\n\
\n\
The type of return value depends on the option, as follows:\n\
\n\
- Options documented by libcurl to return an integer value return a\n\
  Python integer (``long`` on Python 2, ``int`` on Python 3).\n\
- Options documented by libcurl to return a floating point value\n\
  return a Python ``float``.\n\
- Options documented by libcurl to return a string value\n\
  return a Python string (``str`` on Python 2 and Python 3).\n\
  On Python 2, the string contains whatever data libcurl returned.\n\
  On Python 3, the data returned by libcurl is decoded using the\n\
  default string encoding at the time of the call.\n\
  If the data cannot be decoded using the default encoding, ``UnicodeDecodeError``\n\
  is raised. Use :ref:`getinfo_raw <getinfo_raw>`\n\
  to retrieve the data as ``bytes`` in these\n\
  cases.\n\
- ``SSL_ENGINES`` and ``INFO_COOKIELIST`` return a list of strings.\n\
  The same encoding caveats apply; use :ref:`getinfo_raw <getinfo_raw>`\n\
  to retrieve the\n\
  data as a list of byte strings.\n\
- ``INFO_CERTINFO`` returns a list with one element\n\
  per certificate in the chain, starting with the leaf; each element is a\n\
  sequence of *(key, value)* tuples where both ``key`` and ``value`` are\n\
  strings. String encoding caveats apply; use :ref:`getinfo_raw <getinfo_raw>`\n\
  to retrieve\n\
  certificate data as byte strings.\n\
\n\
On Python 2, ``getinfo`` and ``getinfo_raw`` behave identically.\n\
\n\
Example usage::\n\
\n\
    import pycurl\n\
    c = pycurl.Curl()\n\
    c.setopt(pycurl.OPT_CERTINFO, 1)\n\
    c.setopt(pycurl.URL, \"https://python.org\")\n\
    c.setopt(pycurl.FOLLOWLOCATION, 1)\n\
    c.perform()\n\
    print(c.getinfo(pycurl.HTTP_CODE))\n\
    # --> 200\n\
    print(c.getinfo(pycurl.EFFECTIVE_URL))\n\
    # --> \"https://www.python.org/\"\n\
    certinfo = c.getinfo(pycurl.INFO_CERTINFO)\n\
    print(certinfo)\n\
    # --> [(('Subject', 'C = AU, ST = Some-State, O = PycURL test suite,\n\
             CN = localhost'), ('Issuer', 'C = AU, ST = Some-State,\n\
             O = PycURL test suite, OU = localhost, CN = localhost'),\n\
            ('Version', '0'), ...)]\n\
\n\
\n\
Raises pycurl.error exception upon failure.\n\
\n\
.. _curl_easy_getinfo:\n\
    https://curl.haxx.se/libcurl/c/curl_easy_getinfo.html";

PYCURL_INTERNAL const char curl_getinfo_raw_doc[] = "getinfo_raw(option) -> Result\n\
\n\
Extract and return information from a curl session,\n\
returning string data as byte strings.\n\
Corresponds to `curl_easy_getinfo`_ in libcurl.\n\
The ``getinfo_raw`` method should not be called unless\n\
``perform`` has been called and finished.\n\
\n\
*option* is a constant corresponding to one of the\n\
``CURLINFO_*`` constants in libcurl. Most option constant names match\n\
the respective ``CURLINFO_*`` constant names with the ``CURLINFO_`` prefix\n\
removed, for example ``CURLINFO_CONTENT_TYPE`` is accessible as\n\
``pycurl.CONTENT_TYPE``. Exceptions to this rule are as follows:\n\
\n\
- ``CURLINFO_FILETIME`` is mapped as ``pycurl.INFO_FILETIME``\n\
- ``CURLINFO_COOKIELIST`` is mapped as ``pycurl.INFO_COOKIELIST``\n\
- ``CURLINFO_CERTINFO`` is mapped as ``pycurl.INFO_CERTINFO``\n\
- ``CURLINFO_RTSP_CLIENT_CSEQ`` is mapped as ``pycurl.INFO_RTSP_CLIENT_CSEQ``\n\
- ``CURLINFO_RTSP_CSEQ_RECV`` is mapped as ``pycurl.INFO_RTSP_CSEQ_RECV``\n\
- ``CURLINFO_RTSP_SERVER_CSEQ`` is mapped as ``pycurl.INFO_RTSP_SERVER_CSEQ``\n\
- ``CURLINFO_RTSP_SESSION_ID`` is mapped as ``pycurl.INFO_RTSP_SESSION_ID``\n\
\n\
The type of return value depends on the option, as follows:\n\
\n\
- Options documented by libcurl to return an integer value return a\n\
  Python integer (``long`` on Python 2, ``int`` on Python 3).\n\
- Options documented by libcurl to return a floating point value\n\
  return a Python ``float``.\n\
- Options documented by libcurl to return a string value\n\
  return a Python byte string (``str`` on Python 2, ``bytes`` on Python 3).\n\
  The string contains whatever data libcurl returned.\n\
  Use :ref:`getinfo <getinfo>` to retrieve this data as a Unicode string on Python 3.\n\
- ``SSL_ENGINES`` and ``INFO_COOKIELIST`` return a list of byte strings.\n\
  The same encoding caveats apply; use :ref:`getinfo <getinfo>` to retrieve the\n\
  data as a list of potentially Unicode strings.\n\
- ``INFO_CERTINFO`` returns a list with one element\n\
  per certificate in the chain, starting with the leaf; each element is a\n\
  sequence of *(key, value)* tuples where both ``key`` and ``value`` are\n\
  byte strings. String encoding caveats apply; use :ref:`getinfo <getinfo>`\n\
  to retrieve\n\
  certificate data as potentially Unicode strings.\n\
\n\
On Python 2, ``getinfo`` and ``getinfo_raw`` behave identically.\n\
\n\
Example usage::\n\
\n\
    import pycurl\n\
    c = pycurl.Curl()\n\
    c.setopt(pycurl.OPT_CERTINFO, 1)\n\
    c.setopt(pycurl.URL, \"https://python.org\")\n\
    c.setopt(pycurl.FOLLOWLOCATION, 1)\n\
    c.perform()\n\
    print(c.getinfo_raw(pycurl.HTTP_CODE))\n\
    # --> 200\n\
    print(c.getinfo_raw(pycurl.EFFECTIVE_URL))\n\
    # --> b\"https://www.python.org/\"\n\
    certinfo = c.getinfo_raw(pycurl.INFO_CERTINFO)\n\
    print(certinfo)\n\
    # --> [((b'Subject', b'C = AU, ST = Some-State, O = PycURL test suite,\n\
             CN = localhost'), (b'Issuer', b'C = AU, ST = Some-State,\n\
             O = PycURL test suite, OU = localhost, CN = localhost'),\n\
            (b'Version', b'0'), ...)]\n\
\n\
\n\
Raises pycurl.error exception upon failure.\n\
\n\
*Added in version 7.43.0.2.*\n\
\n\
.. _curl_easy_getinfo:\n\
    https://curl.haxx.se/libcurl/c/curl_easy_getinfo.html";

PYCURL_INTERNAL const char curl_pause_doc[] = "pause(bitmask) -> None\n\
\n\
Pause or unpause a curl handle. Bitmask should be a value such as\n\
PAUSE_RECV or PAUSE_CONT.\n\
\n\
Corresponds to `curl_easy_pause`_ in libcurl. The argument should be\n\
derived from the ``PAUSE_RECV``, ``PAUSE_SEND``, ``PAUSE_ALL`` and\n\
``PAUSE_CONT`` constants.\n\
\n\
Raises pycurl.error exception upon failure.\n\
\n\
.. _curl_easy_pause: https://curl.haxx.se/libcurl/c/curl_easy_pause.html";

PYCURL_INTERNAL const char curl_perform_doc[] = "perform() -> None\n\
\n\
Perform a file transfer.\n\
\n\
Corresponds to `curl_easy_perform`_ in libcurl.\n\
\n\
Raises pycurl.error exception upon failure.\n\
\n\
.. _curl_easy_perform:\n\
    https://curl.haxx.se/libcurl/c/curl_easy_perform.html";

PYCURL_INTERNAL const char curl_perform_rb_doc[] = "perform_rb() -> response_body\n\
\n\
Perform a file transfer and return response body as a byte string.\n\
\n\
This method arranges for response body to be saved in a StringIO\n\
(Python 2) or BytesIO (Python 3) instance, then invokes :ref:`perform <perform>`\n\
to perform the file transfer, then returns the value of the StringIO/BytesIO\n\
instance which is a ``str`` instance on Python 2 and ``bytes`` instance\n\
on Python 3. Errors during transfer raise ``pycurl.error`` exceptions\n\
just like in :ref:`perform <perform>`.\n\
\n\
Use :ref:`perform_rs <perform_rs>` to retrieve response body as a string\n\
(``str`` instance on both Python 2 and 3).\n\
\n\
Raises ``pycurl.error`` exception upon failure.\n\
\n\
*Added in version 7.43.0.2.*";

PYCURL_INTERNAL const char curl_perform_rs_doc[] = "perform_rs() -> response_body\n\
\n\
Perform a file transfer and return response body as a string.\n\
\n\
On Python 2, this method arranges for response body to be saved in a StringIO\n\
instance, then invokes :ref:`perform <perform>`\n\
to perform the file transfer, then returns the value of the StringIO instance.\n\
This behavior is identical to :ref:`perform_rb <perform_rb>`.\n\
\n\
On Python 3, this method arranges for response body to be saved in a BytesIO\n\
instance, then invokes :ref:`perform <perform>`\n\
to perform the file transfer, then decodes the response body in Python's\n\
default encoding and returns the decoded body as a Unicode string\n\
(``str`` instance). *Note:* decoding happens after the transfer finishes,\n\
thus an encoding error implies the transfer/network operation succeeded.\n\
\n\
Any transfer errors raise ``pycurl.error`` exception,\n\
just like in :ref:`perform <perform>`.\n\
\n\
Use :ref:`perform_rb <perform_rb>` to retrieve response body as a byte\n\
string (``bytes`` instance on Python 3) without attempting to decode it.\n\
\n\
Raises ``pycurl.error`` exception upon failure.\n\
\n\
*Added in version 7.43.0.2.*";

PYCURL_INTERNAL const char curl_reset_doc[] = "reset() -> None\n\
\n\
Reset all options set on curl handle to default values, but preserves\n\
live connections, session ID cache, DNS cache, cookies, and shares.\n\
\n\
Corresponds to `curl_easy_reset`_ in libcurl.\n\
\n\
.. _curl_easy_reset: https://curl.haxx.se/libcurl/c/curl_easy_reset.html";

PYCURL_INTERNAL const char curl_set_ca_certs_doc[] = "set_ca_certs() -> None\n\
\n\
Load ca certs from provided unicode string.\n\
\n\
Note that certificates will be added only when cURL starts new connection.";

PYCURL_INTERNAL const char curl_setopt_doc[] = "setopt(option, value) -> None\n\
\n\
Set curl session option. Corresponds to `curl_easy_setopt`_ in libcurl.\n\
\n\
*option* specifies which option to set. PycURL defines constants\n\
corresponding to ``CURLOPT_*`` constants in libcurl, except that\n\
the ``CURLOPT_`` prefix is removed. For example, ``CURLOPT_URL`` is\n\
exposed in PycURL as ``pycurl.URL``, with some exceptions as detailed below.\n\
For convenience, ``CURLOPT_*``\n\
constants are also exposed on the Curl objects themselves::\n\
\n\
    import pycurl\n\
    c = pycurl.Curl()\n\
    c.setopt(pycurl.URL, \"http://www.python.org/\")\n\
    # Same as:\n\
    c.setopt(c.URL, \"http://www.python.org/\")\n\
\n\
The following are exceptions to option constant naming convention:\n\
\n\
- ``CURLOPT_FILETIME`` is mapped as ``pycurl.OPT_FILETIME``\n\
- ``CURLOPT_CERTINFO`` is mapped as ``pycurl.OPT_CERTINFO``\n\
- ``CURLOPT_COOKIELIST`` is mapped as ``pycurl.COOKIELIST``\n\
  and, as of PycURL 7.43.0.2, also as ``pycurl.OPT_COOKIELIST``\n\
- ``CURLOPT_RTSP_CLIENT_CSEQ`` is mapped as ``pycurl.OPT_RTSP_CLIENT_CSEQ``\n\
- ``CURLOPT_RTSP_REQUEST`` is mapped as ``pycurl.OPT_RTSP_REQUEST``\n\
- ``CURLOPT_RTSP_SERVER_CSEQ`` is mapped as ``pycurl.OPT_RTSP_SERVER_CSEQ``\n\
- ``CURLOPT_RTSP_SESSION_ID`` is mapped as ``pycurl.OPT_RTSP_SESSION_ID``\n\
- ``CURLOPT_RTSP_STREAM_URI`` is mapped as ``pycurl.OPT_RTSP_STREAM_URI``\n\
- ``CURLOPT_RTSP_TRANSPORT`` is mapped as ``pycurl.OPT_RTSP_TRANSPORT``\n\
\n\
*value* specifies the value to set the option to. Different options accept\n\
values of different types:\n\
\n\
- Options specified by `curl_easy_setopt`_ as accepting ``1`` or an\n\
  integer value accept Python integers, long integers (on Python 2.x) and\n\
  booleans::\n\
\n\
    c.setopt(pycurl.FOLLOWLOCATION, True)\n\
    c.setopt(pycurl.FOLLOWLOCATION, 1)\n\
    # Python 2.x only:\n\
    c.setopt(pycurl.FOLLOWLOCATION, 1L)\n\
\n\
- Options specified as accepting strings by ``curl_easy_setopt`` accept\n\
  byte strings (``str`` on Python 2, ``bytes`` on Python 3) and\n\
  Unicode strings with ASCII code points only.\n\
  For more information, please refer to :ref:`unicode`. Example::\n\
\n\
    c.setopt(pycurl.URL, \"http://www.python.org/\")\n\
    c.setopt(pycurl.URL, u\"http://www.python.org/\")\n\
    # Python 3.x only:\n\
    c.setopt(pycurl.URL, b\"http://www.python.org/\")\n\
\n\
- ``HTTP200ALIASES``, ``HTTPHEADER``, ``POSTQUOTE``, ``PREQUOTE``,\n\
  ``PROXYHEADER`` and\n\
  ``QUOTE`` accept a list or tuple of strings. The same rules apply to these\n\
  strings as do to string option values. Example::\n\
\n\
    c.setopt(pycurl.HTTPHEADER, [\"Accept:\"])\n\
    c.setopt(pycurl.HTTPHEADER, (\"Accept:\",))\n\
\n\
- ``READDATA`` accepts a file object or any Python object which has\n\
  a ``read`` method. On Python 2, a file object will be passed directly\n\
  to libcurl and may result in greater transfer efficiency, unless\n\
  PycURL has been compiled with ``AVOID_STDIO`` option.\n\
  On Python 3 and on Python 2 when the value is not a true file object,\n\
  ``READDATA`` is emulated in PycURL via ``READFUNCTION``.\n\
  The file should generally be opened in binary mode. Example::\n\
\n\
    f = open('file.txt', 'rb')\n\
    c.setopt(c.READDATA, f)\n\
\n\
- ``WRITEDATA`` and ``WRITEHEADER`` accept a file object or any Python\n\
  object which has a ``write`` method. On Python 2, a file object will\n\
  be passed directly to libcurl and may result in greater transfer efficiency,\n\
  unless PycURL has been compiled with ``AVOID_STDIO`` option.\n\
  On Python 3 and on Python 2 when the value is not a true file object,\n\
  ``WRITEDATA`` is emulated in PycURL via ``WRITEFUNCTION``.\n\
  The file should generally be opened in binary mode. Example::\n\
\n\
    f = open('/dev/null', 'wb')\n\
    c.setopt(c.WRITEDATA, f)\n\
\n\
- ``*FUNCTION`` options accept a function. Supported callbacks are documented\n\
  in :ref:`callbacks`. Example::\n\
\n\
    # Python 2\n\
    import StringIO\n\
    b = StringIO.StringIO()\n\
    c.setopt(pycurl.WRITEFUNCTION, b.write)\n\
\n\
- ``SHARE`` option accepts a :ref:`curlshareobject`.\n\
\n\
It is possible to set integer options - and only them - that PycURL does\n\
not know about by using the numeric value of the option constant directly.\n\
For example, ``pycurl.VERBOSE`` has the value 42, and may be set as follows::\n\
\n\
    c.setopt(42, 1)\n\
\n\
*setopt* can reset some options to their default value, performing the job of\n\
:py:meth:`pycurl.Curl.unsetopt`, if ``None`` is passed\n\
for the option value. The following two calls are equivalent::\n\
\n\
    c.setopt(c.URL, None)\n\
    c.unsetopt(c.URL)\n\
\n\
Raises TypeError when the option value is not of a type accepted by the\n\
respective option, and pycurl.error exception when libcurl rejects the\n\
option or its value.\n\
\n\
.. _curl_easy_setopt: https://curl.haxx.se/libcurl/c/curl_easy_setopt.html";

PYCURL_INTERNAL const char curl_setopt_string_doc[] = "setopt_string(option, value) -> None\n\
\n\
Set curl session option to a string value.\n\
\n\
This method allows setting string options that are not officially supported\n\
by PycURL, for example because they did not exist when the version of PycURL\n\
being used was released.\n\
:py:meth:`pycurl.Curl.setopt` should be used for setting options that\n\
PycURL knows about.\n\
\n\
**Warning:** No checking is performed that *option* does, in fact,\n\
expect a string value. Using this method incorrectly can crash the program\n\
and may lead to a security vulnerability.\n\
Furthermore, it is on the application to ensure that the *value* object\n\
does not get garbage collected while libcurl is using it.\n\
libcurl copies most string options but not all; one option whose value\n\
is not copied by libcurl is `CURLOPT_POSTFIELDS`_.\n\
\n\
*option* would generally need to be given as an integer literal rather than\n\
a symbolic constant.\n\
\n\
*value* can be a binary string or a Unicode string using ASCII code points,\n\
same as with string options given to PycURL elsewhere.\n\
\n\
Example setting URL via ``setopt_string``::\n\
\n\
    import pycurl\n\
    c = pycurl.Curl()\n\
    c.setopt_string(10002, \"http://www.python.org/\")\n\
\n\
.. _CURLOPT_POSTFIELDS: https://curl.haxx.se/libcurl/c/CURLOPT_POSTFIELDS.html";

PYCURL_INTERNAL const char curl_unsetopt_doc[] = "unsetopt(option) -> None\n\
\n\
Reset curl session option to its default value.\n\
\n\
Only some curl options may be reset via this method.\n\
\n\
libcurl does not provide a general way to reset a single option to its default value;\n\
:py:meth:`pycurl.Curl.reset` resets all options to their default values,\n\
otherwise :py:meth:`pycurl.Curl.setopt` must be called with whatever value\n\
is the default. For convenience, PycURL provides this unsetopt method\n\
to reset some of the options to their default values.\n\
\n\
Raises pycurl.error exception on failure.\n\
\n\
``c.unsetopt(option)`` is equivalent to ``c.setopt(option, None)``.";

PYCURL_INTERNAL const char multi_doc[] = "CurlMulti() -> New CurlMulti object\n\
\n\
Creates a new :ref:`curlmultiobject` which corresponds to\n\
a ``CURLM`` handle in libcurl.";

PYCURL_INTERNAL const char multi_add_handle_doc[] = "add_handle(Curl object) -> None\n\
\n\
Corresponds to `curl_multi_add_handle`_ in libcurl. This method adds an\n\
existing and valid Curl object to the CurlMulti object.\n\
\n\
*Changed in version 7.43.0.2:* add_handle now ensures that the Curl object\n\
is not garbage collected while it is being used by a CurlMulti object.\n\
Previously application had to maintain an outstanding reference to the Curl\n\
object to keep it from being garbage collected.\n\
\n\
.. _curl_multi_add_handle:\n\
    https://curl.haxx.se/libcurl/c/curl_multi_add_handle.html";

PYCURL_INTERNAL const char multi_assign_doc[] = "assign(sockfd, object) -> None\n\
\n\
Creates an association in the multi handle between the given socket and\n\
a private object in the application.\n\
Corresponds to `curl_multi_assign`_ in libcurl.\n\
\n\
.. _curl_multi_assign: https://curl.haxx.se/libcurl/c/curl_multi_assign.html";

PYCURL_INTERNAL const char multi_close_doc[] = "close() -> None\n\
\n\
Corresponds to `curl_multi_cleanup`_ in libcurl. This method is\n\
automatically called by pycurl when a CurlMulti object no longer has any\n\
references to it, but can also be called explicitly.\n\
\n\
.. _curl_multi_cleanup:\n\
    https://curl.haxx.se/libcurl/c/curl_multi_cleanup.html";

PYCURL_INTERNAL const char multi_fdset_doc[] = "fdset() -> tuple of lists with active file descriptors, readable, writeable, exceptions\n\
\n\
Returns a tuple of three lists that can be passed to the select.select() method.\n\
\n\
Corresponds to `curl_multi_fdset`_ in libcurl. This method extracts the\n\
file descriptor information from a CurlMulti object. The returned lists can\n\
be used with the ``select`` module to poll for events.\n\
\n\
Example usage::\n\
\n\
    import pycurl\n\
    c = pycurl.Curl()\n\
    c.setopt(pycurl.URL, \"https://curl.haxx.se\")\n\
    m = pycurl.CurlMulti()\n\
    m.add_handle(c)\n\
    while 1:\n\
        ret, num_handles = m.perform()\n\
        if ret != pycurl.E_CALL_MULTI_PERFORM: break\n\
    while num_handles:\n\
        apply(select.select, m.fdset() + (1,))\n\
        while 1:\n\
            ret, num_handles = m.perform()\n\
            if ret != pycurl.E_CALL_MULTI_PERFORM: break\n\
\n\
.. _curl_multi_fdset:\n\
    https://curl.haxx.se/libcurl/c/curl_multi_fdset.html";

PYCURL_INTERNAL const char multi_info_read_doc[] = "info_read([max_objects]) -> tuple(number of queued messages, a list of successful objects, a list of failed objects)\n\
\n\
Returns a tuple (number of queued handles, [curl objects]).\n\
\n\
Corresponds to the `curl_multi_info_read`_ function in libcurl. This\n\
method extracts at most *max* messages from the multi stack and returns them\n\
in two lists. The first list contains the handles which completed\n\
successfully and the second list contains a tuple *(curl object, curl error\n\
number, curl error message)* for each failed curl object. The number of\n\
queued messages after this method has been called is also returned.\n\
\n\
.. _curl_multi_info_read:\n\
    https://curl.haxx.se/libcurl/c/curl_multi_info_read.html";

PYCURL_INTERNAL const char multi_perform_doc[] = "perform() -> tuple of status and the number of active Curl objects\n\
\n\
Corresponds to `curl_multi_perform`_ in libcurl.\n\
\n\
.. _curl_multi_perform:\n\
    https://curl.haxx.se/libcurl/c/curl_multi_perform.html";

PYCURL_INTERNAL const char multi_remove_handle_doc[] = "remove_handle(Curl object) -> None\n\
\n\
Corresponds to `curl_multi_remove_handle`_ in libcurl. This method\n\
removes an existing and valid Curl object from the CurlMulti object.\n\
\n\
.. _curl_multi_remove_handle:\n\
    https://curl.haxx.se/libcurl/c/curl_multi_remove_handle.html";

PYCURL_INTERNAL const char multi_select_doc[] = "select([timeout]) -> number of ready file descriptors or -1 on timeout\n\
\n\
Returns result from doing a select() on the curl multi file descriptor\n\
with the given timeout.\n\
\n\
This is a convenience function which simplifies the combined use of\n\
``fdset()`` and the ``select`` module.\n\
\n\
Example usage::\n\
\n\
    import pycurl\n\
    c = pycurl.Curl()\n\
    c.setopt(pycurl.URL, \"https://curl.haxx.se\")\n\
    m = pycurl.CurlMulti()\n\
    m.add_handle(c)\n\
    while 1:\n\
        ret, num_handles = m.perform()\n\
        if ret != pycurl.E_CALL_MULTI_PERFORM: break\n\
    while num_handles:\n\
        ret = m.select(1.0)\n\
        if ret == -1:  continue\n\
        while 1:\n\
            ret, num_handles = m.perform()\n\
            if ret != pycurl.E_CALL_MULTI_PERFORM: break";

PYCURL_INTERNAL const char multi_setopt_doc[] = "setopt(option, value) -> None\n\
\n\
Set curl multi option. Corresponds to `curl_multi_setopt`_ in libcurl.\n\
\n\
*option* specifies which option to set. PycURL defines constants\n\
corresponding to ``CURLMOPT_*`` constants in libcurl, except that\n\
the ``CURLMOPT_`` prefix is replaced with ``M_`` prefix.\n\
For example, ``CURLMOPT_PIPELINING`` is\n\
exposed in PycURL as ``pycurl.M_PIPELINING``. For convenience, ``CURLMOPT_*``\n\
constants are also exposed on CurlMulti objects::\n\
\n\
    import pycurl\n\
    m = pycurl.CurlMulti()\n\
    m.setopt(pycurl.M_PIPELINING, 1)\n\
    # Same as:\n\
    m.setopt(m.M_PIPELINING, 1)\n\
\n\
*value* specifies the value to set the option to. Different options accept\n\
values of different types:\n\
\n\
- Options specified by `curl_multi_setopt`_ as accepting ``1`` or an\n\
  integer value accept Python integers, long integers (on Python 2.x) and\n\
  booleans::\n\
\n\
    m.setopt(pycurl.M_PIPELINING, True)\n\
    m.setopt(pycurl.M_PIPELINING, 1)\n\
    # Python 2.x only:\n\
    m.setopt(pycurl.M_PIPELINING, 1L)\n\
\n\
- ``*FUNCTION`` options accept a function. Supported callbacks are\n\
  ``CURLMOPT_SOCKETFUNCTION`` AND ``CURLMOPT_TIMERFUNCTION``. Please refer to\n\
  the PycURL test suite for examples on using the callbacks.\n\
\n\
Raises TypeError when the option value is not of a type accepted by the\n\
respective option, and pycurl.error exception when libcurl rejects the\n\
option or its value.\n\
\n\
.. _curl_multi_setopt: https://curl.haxx.se/libcurl/c/curl_multi_setopt.html";

PYCURL_INTERNAL const char multi_socket_action_doc[] = "socket_action(sockfd, ev_bitmask) -> tuple\n\
\n\
Returns result from doing a socket_action() on the curl multi file descriptor\n\
with the given timeout.\n\
Corresponds to `curl_multi_socket_action`_ in libcurl.\n\
\n\
.. _curl_multi_socket_action: https://curl.haxx.se/libcurl/c/curl_multi_socket_action.html";

PYCURL_INTERNAL const char multi_socket_all_doc[] = "socket_all() -> Tuple.\n\
\n\
Returns result from doing a socket_all() on the curl multi file descriptor\n\
with the given timeout.";

PYCURL_INTERNAL const char multi_timeout_doc[] = "timeout() -> int\n\
\n\
Returns how long to wait for action before proceeding.\n\
Corresponds to `curl_multi_timeout`_ in libcurl.\n\
\n\
.. _curl_multi_timeout: https://curl.haxx.se/libcurl/c/curl_multi_timeout.html";

PYCURL_INTERNAL const char pycurl_global_cleanup_doc[] = "global_cleanup() -> None\n\
\n\
Cleanup curl environment.\n\
\n\
Corresponds to `curl_global_cleanup`_ in libcurl.\n\
\n\
.. _curl_global_cleanup: https://curl.haxx.se/libcurl/c/curl_global_cleanup.html";

PYCURL_INTERNAL const char pycurl_global_init_doc[] = "global_init(option) -> None\n\
\n\
Initialize curl environment.\n\
\n\
*option* is one of the constants pycurl.GLOBAL_SSL, pycurl.GLOBAL_WIN32,\n\
pycurl.GLOBAL_ALL, pycurl.GLOBAL_NOTHING, pycurl.GLOBAL_DEFAULT.\n\
\n\
Corresponds to `curl_global_init`_ in libcurl.\n\
\n\
.. _curl_global_init: https://curl.haxx.se/libcurl/c/curl_global_init.html";

PYCURL_INTERNAL const char pycurl_module_doc[] = "This module implements an interface to the cURL library.\n\
\n\
Types:\n\
\n\
Curl() -> New object.  Create a new curl object.\n\
CurlMulti() -> New object.  Create a new curl multi object.\n\
CurlShare() -> New object.  Create a new curl share object.\n\
\n\
Functions:\n\
\n\
global_init(option) -> None.  Initialize curl environment.\n\
global_cleanup() -> None.  Cleanup curl environment.\n\
version_info() -> tuple.  Return version information.";

PYCURL_INTERNAL const char pycurl_version_info_doc[] = "version_info() -> tuple\n\
\n\
Returns a 12-tuple with the version info.\n\
\n\
Corresponds to `curl_version_info`_ in libcurl. Returns a tuple of\n\
information which is similar to the ``curl_version_info_data`` struct\n\
returned by ``curl_version_info()`` in libcurl.\n\
\n\
Example usage::\n\
\n\
    >>> import pycurl\n\
    >>> pycurl.version_info()\n\
    (3, '7.33.0', 467200, 'amd64-portbld-freebsd9.1', 33436, 'OpenSSL/0.9.8x',\n\
    0, '1.2.7', ('dict', 'file', 'ftp', 'ftps', 'gopher', 'http', 'https',\n\
    'imap', 'imaps', 'pop3', 'pop3s', 'rtsp', 'smtp', 'smtps', 'telnet',\n\
    'tftp'), None, 0, None)\n\
\n\
.. _curl_version_info: https://curl.haxx.se/libcurl/c/curl_version_info.html";

PYCURL_INTERNAL const char share_doc[] = "CurlShare() -> New CurlShare object\n\
\n\
Creates a new :ref:`curlshareobject` which corresponds to a\n\
``CURLSH`` handle in libcurl. CurlShare objects is what you pass as an\n\
argument to the SHARE option on :ref:`Curl objects <curlobject>`.";

PYCURL_INTERNAL const char share_close_doc[] = "close() -> None\n\
\n\
Close shared handle.\n\
\n\
Corresponds to `curl_share_cleanup`_ in libcurl. This method is\n\
automatically called by pycurl when a CurlShare object no longer has\n\
any references to it, but can also be called explicitly.\n\
\n\
.. _curl_share_cleanup:\n\
    https://curl.haxx.se/libcurl/c/curl_share_cleanup.html";

PYCURL_INTERNAL const char share_setopt_doc[] = "setopt(option, value) -> None\n\
\n\
Set curl share option.\n\
\n\
Corresponds to `curl_share_setopt`_ in libcurl, where *option* is\n\
specified with the ``CURLSHOPT_*`` constants in libcurl, except that the\n\
``CURLSHOPT_`` prefix has been changed to ``SH_``. Currently, *value* must be\n\
either ``LOCK_DATA_COOKIE`` or ``LOCK_DATA_DNS``.\n\
\n\
Example usage::\n\
\n\
    import pycurl\n\
    curl = pycurl.Curl()\n\
    s = pycurl.CurlShare()\n\
    s.setopt(pycurl.SH_SHARE, pycurl.LOCK_DATA_COOKIE)\n\
    s.setopt(pycurl.SH_SHARE, pycurl.LOCK_DATA_DNS)\n\
    curl.setopt(pycurl.URL, 'https://curl.haxx.se')\n\
    curl.setopt(pycurl.SHARE, s)\n\
    curl.perform()\n\
    curl.close()\n\
\n\
Raises pycurl.error exception upon failure.\n\
\n\
.. _curl_share_setopt:\n\
    https://curl.haxx.se/libcurl/c/curl_share_setopt.html";




/*************************************************************************
// static utility functions
**************************************************************************/


/* assert some CurlObject invariants */
PYCURL_INTERNAL void
assert_curl_state(const CurlObject *self)
{
    assert(self != NULL);
    assert(Py_TYPE(self) == p_Curl_Type);
#ifdef WITH_THREAD
    (void) pycurl_get_thread_state(self);
#endif
}


/* check state for methods */
PYCURL_INTERNAL int
check_curl_state(const CurlObject *self, int flags, const char *name)
{
    assert_curl_state(self);
    if ((flags & 1) && self->handle == NULL) {
        PyErr_Format(ErrorObject, "cannot invoke %s() - no curl handle", name);
        return -1;
    }
#ifdef WITH_THREAD
    if ((flags & 2) && pycurl_get_thread_state(self) != NULL) {
        PyErr_Format(ErrorObject, "cannot invoke %s() - perform() is currently running", name);
        return -1;
    }
#endif
    return 0;
}


/*************************************************************************
// CurlObject
**************************************************************************/

/* --------------- construct/destruct (i.e. open/close) --------------- */

/* initializer - used to intialize curl easy handles for use with pycurl */
static int
util_curl_init(CurlObject *self)
{
    int res;

    /* Set curl error buffer and zero it */
    res = curl_easy_setopt(self->handle, CURLOPT_ERRORBUFFER, self->error);
    if (res != CURLE_OK) {
        return (-1);
    }
    memset(self->error, 0, sizeof(self->error));

    /* Set backreference */
    res = curl_easy_setopt(self->handle, CURLOPT_PRIVATE, (char *) self);
    if (res != CURLE_OK) {
        return (-1);
    }

    /* Enable NOPROGRESS by default, i.e. no progress output */
    res = curl_easy_setopt(self->handle, CURLOPT_NOPROGRESS, (long)1);
    if (res != CURLE_OK) {
        return (-1);
    }

    /* Disable VERBOSE by default, i.e. no verbose output */
    res = curl_easy_setopt(self->handle, CURLOPT_VERBOSE, (long)0);
    if (res != CURLE_OK) {
        return (-1);
    }

    /* Set default USERAGENT */
    assert(g_pycurl_useragent);
    res = curl_easy_setopt(self->handle, CURLOPT_USERAGENT, g_pycurl_useragent);
    if (res != CURLE_OK) {
        return (-1);
    }
    return (0);
}

/* constructor */
PYCURL_INTERNAL CurlObject *
do_curl_new(PyTypeObject *subtype, PyObject *args, PyObject *kwds)
{
    CurlObject *self;
    int res;
    int *ptr;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "", empty_keywords)) {
        return NULL;
    }

    /* Allocate python curl object */
    self = (CurlObject *) p_Curl_Type->tp_alloc(p_Curl_Type, 0);
    if (self == NULL)
        return NULL;

    /* tp_alloc is expected to return zeroed memory */
    for (ptr = (int *) &self->dict;
        ptr < (int *) (((char *) self) + sizeof(CurlObject));
        ++ptr)
            assert(*ptr == 0);

    /* Initialize curl handle */
    self->handle = curl_easy_init();
    if (self->handle == NULL)
        goto error;

    res = util_curl_init(self);
    if (res < 0)
            goto error;
    /* Success - return new object */
    return self;

error:
    Py_DECREF(self);    /* this also closes self->handle */
    PyErr_SetString(ErrorObject, "initializing curl failed");
    return NULL;
}


/* util function shared by close() and clear() */
PYCURL_INTERNAL void
util_curl_xdecref(CurlObject *self, int flags, CURL *handle)
{
    if (flags & PYCURL_MEMGROUP_ATTRDICT) {
        /* Decrement refcount for attributes dictionary. */
        Py_CLEAR(self->dict);
    }

    if (flags & PYCURL_MEMGROUP_MULTI) {
        /* Decrement refcount for multi_stack. */
        if (self->multi_stack != NULL) {
            CurlMultiObject *multi_stack = self->multi_stack;
            self->multi_stack = NULL;
            if (multi_stack->multi_handle != NULL && handle != NULL) {
                /* TODO this is where we could remove the easy object
                from the multi object's easy_object_dict, but this
                requires us to have a reference to the multi object
                which right now we don't. */
                (void) curl_multi_remove_handle(multi_stack->multi_handle, handle);
            }
            Py_DECREF(multi_stack);
        }
    }

    if (flags & PYCURL_MEMGROUP_CALLBACK) {
        /* Decrement refcount for python callbacks. */
        Py_CLEAR(self->w_cb);
        Py_CLEAR(self->h_cb);
        Py_CLEAR(self->r_cb);
        Py_CLEAR(self->pro_cb);
#if LIBCURL_VERSION_NUM >= MAKE_LIBCURL_VERSION(7, 32, 0)
        Py_CLEAR(self->xferinfo_cb);
#endif
        Py_CLEAR(self->debug_cb);
        Py_CLEAR(self->ioctl_cb);
        Py_CLEAR(self->seek_cb);
        Py_CLEAR(self->opensocket_cb);
#if LIBCURL_VERSION_NUM >= MAKE_LIBCURL_VERSION(7, 21, 7)
        Py_CLEAR(self->closesocket_cb);
#endif
        Py_CLEAR(self->sockopt_cb);
        Py_CLEAR(self->ssh_key_cb);
    }

    if (flags & PYCURL_MEMGROUP_FILE) {
        /* Decrement refcount for python file objects. */
        Py_CLEAR(self->readdata_fp);
        Py_CLEAR(self->writedata_fp);
        Py_CLEAR(self->writeheader_fp);
    }

    if (flags & PYCURL_MEMGROUP_POSTFIELDS) {
        /* Decrement refcount for postfields object */
        Py_CLEAR(self->postfields_obj);
    }

    if (flags & PYCURL_MEMGROUP_SHARE) {
        /* Decrement refcount for share objects. */
        if (self->share != NULL) {
            CurlShareObject *share = self->share;
            self->share = NULL;
            if (share->share_handle != NULL && handle != NULL) {
                curl_easy_setopt(handle, CURLOPT_SHARE, NULL);
            }
            Py_DECREF(share);
        }
    }

    if (flags & PYCURL_MEMGROUP_HTTPPOST) {
        /* Decrement refcounts for httppost related references. */
        Py_CLEAR(self->httppost_ref_list);
    }

    if (flags & PYCURL_MEMGROUP_CACERTS) {
        /* Decrement refcounts for ca certs related references. */
        Py_CLEAR(self->ca_certs_obj);
    }
}


static void
util_curl_close(CurlObject *self)
{
    CURL *handle;

    /* Zero handle and thread-state to disallow any operations to be run
     * from now on */
    assert(self != NULL);
    assert(Py_TYPE(self) == p_Curl_Type);
    handle = self->handle;
    self->handle = NULL;
    if (handle == NULL) {
        /* Some paranoia assertions just to make sure the object
         * deallocation problem is finally really fixed... */
#ifdef WITH_THREAD
        assert(self->state == NULL);
#endif
        assert(self->multi_stack == NULL);
        assert(self->share == NULL);
        return;             /* already closed */
    }
#ifdef WITH_THREAD
    self->state = NULL;
#endif

    /* Decref multi stuff which uses this handle */
    util_curl_xdecref(self, PYCURL_MEMGROUP_MULTI, handle);
    /* Decref share which uses this handle */
    util_curl_xdecref(self, PYCURL_MEMGROUP_SHARE, handle);

    /* Cleanup curl handle - must be done without the gil */
    Py_BEGIN_ALLOW_THREADS
    curl_easy_cleanup(handle);
    Py_END_ALLOW_THREADS
    handle = NULL;

    /* Decref easy related objects */
    util_curl_xdecref(self, PYCURL_MEMGROUP_EASY, handle);

    if (self->weakreflist != NULL) {
        PyObject_ClearWeakRefs((PyObject *) self);
    }

    /* Free all variables allocated by setopt */
#undef SFREE
#define SFREE(v)   if ((v) != NULL) (curl_formfree(v), (v) = NULL)
    SFREE(self->httppost);
#undef SFREE
#define SFREE(v)   if ((v) != NULL) (curl_slist_free_all(v), (v) = NULL)
    SFREE(self->httpheader);
#if LIBCURL_VERSION_NUM >= MAKE_LIBCURL_VERSION(7, 37, 0)
    SFREE(self->proxyheader);
#endif
    SFREE(self->http200aliases);
    SFREE(self->quote);
    SFREE(self->postquote);
    SFREE(self->prequote);
    SFREE(self->telnetoptions);
#ifdef HAVE_CURLOPT_RESOLVE
    SFREE(self->resolve);
#endif
#ifdef HAVE_CURL_7_20_0_OPTS
    SFREE(self->mail_rcpt);
#endif
#ifdef HAVE_CURLOPT_CONNECT_TO
    SFREE(self->connect_to);
#endif
#undef SFREE
}


PYCURL_INTERNAL void
do_curl_dealloc(CurlObject *self)
{
    PyObject_GC_UnTrack(self);
    Py_TRASHCAN_SAFE_BEGIN(self);

    Py_CLEAR(self->dict);
    util_curl_close(self);

    Curl_Type.tp_free(self);
    Py_TRASHCAN_SAFE_END(self);
}


static PyObject *
do_curl_close(CurlObject *self)
{
    if (check_curl_state(self, 2, "close") != 0) {
        return NULL;
    }
    util_curl_close(self);
    Py_RETURN_NONE;
}


/* --------------- GC support --------------- */

/* Drop references that may have created reference cycles. */
PYCURL_INTERNAL int
do_curl_clear(CurlObject *self)
{
#ifdef WITH_THREAD
    assert(pycurl_get_thread_state(self) == NULL);
#endif
    util_curl_xdecref(self, PYCURL_MEMGROUP_ALL, self->handle);
    return 0;
}

/* Traverse all refcounted objects. */
PYCURL_INTERNAL int
do_curl_traverse(CurlObject *self, visitproc visit, void *arg)
{
    int err;
#undef VISIT
#define VISIT(v)    if ((v) != NULL && ((err = visit(v, arg)) != 0)) return err

    VISIT(self->dict);
    VISIT((PyObject *) self->multi_stack);
    VISIT((PyObject *) self->share);

    VISIT(self->w_cb);
    VISIT(self->h_cb);
    VISIT(self->r_cb);
    VISIT(self->pro_cb);
#if LIBCURL_VERSION_NUM >= MAKE_LIBCURL_VERSION(7, 32, 0)
    VISIT(self->xferinfo_cb);
#endif
    VISIT(self->debug_cb);
    VISIT(self->ioctl_cb);
    VISIT(self->seek_cb);
    VISIT(self->opensocket_cb);
#if LIBCURL_VERSION_NUM >= MAKE_LIBCURL_VERSION(7, 21, 7)
    VISIT(self->closesocket_cb);
#endif
    VISIT(self->sockopt_cb);
    VISIT(self->ssh_key_cb);

    VISIT(self->readdata_fp);
    VISIT(self->writedata_fp);
    VISIT(self->writeheader_fp);

    VISIT(self->postfields_obj);

    VISIT(self->ca_certs_obj);

    return 0;
#undef VISIT
}


/* ------------------------ reset ------------------------ */

static PyObject*
do_curl_reset(CurlObject *self)
{
    int res;

    curl_easy_reset(self->handle);

    /* Decref easy interface related objects */
    util_curl_xdecref(self, PYCURL_MEMGROUP_EASY, self->handle);

    /* Free all variables allocated by setopt */
#undef SFREE
#define SFREE(v)   if ((v) != NULL) (curl_formfree(v), (v) = NULL)
    SFREE(self->httppost);
#undef SFREE
#define SFREE(v)   if ((v) != NULL) (curl_slist_free_all(v), (v) = NULL)
    SFREE(self->httpheader);
#if LIBCURL_VERSION_NUM >= MAKE_LIBCURL_VERSION(7, 37, 0)
    SFREE(self->proxyheader);
#endif
    SFREE(self->http200aliases);
    SFREE(self->quote);
    SFREE(self->postquote);
    SFREE(self->prequote);
    SFREE(self->telnetoptions);
#ifdef HAVE_CURLOPT_RESOLVE
    SFREE(self->resolve);
#endif
#ifdef HAVE_CURL_7_20_0_OPTS
    SFREE(self->mail_rcpt);
#endif
#ifdef HAVE_CURLOPT_CONNECT_TO
    SFREE(self->connect_to);
#endif
#undef SFREE
    res = util_curl_init(self);
    if (res < 0) {
        Py_DECREF(self);    /* this also closes self->handle */
        PyErr_SetString(ErrorObject, "resetting curl failed");
        return NULL;
    }

    Py_RETURN_NONE;
}


static PyObject *do_curl_getstate(CurlObject *self)
{
    PyErr_SetString(PyExc_TypeError, "Curl objects do not support serialization");
    return NULL;
}


static PyObject *do_curl_setstate(CurlObject *self, PyObject *args)
{
    PyErr_SetString(PyExc_TypeError, "Curl objects do not support deserialization");
    return NULL;
}


/*************************************************************************
// type definitions
**************************************************************************/

/* --------------- methods --------------- */

PYCURL_INTERNAL PyMethodDef curlobject_methods[] = {
    {"close", (PyCFunction)do_curl_close, METH_NOARGS, curl_close_doc},
    {"errstr", (PyCFunction)do_curl_errstr, METH_NOARGS, curl_errstr_doc},
    {"errstr_raw", (PyCFunction)do_curl_errstr_raw, METH_NOARGS, curl_errstr_raw_doc},
    {"getinfo", (PyCFunction)do_curl_getinfo, METH_VARARGS, curl_getinfo_doc},
    {"getinfo_raw", (PyCFunction)do_curl_getinfo_raw, METH_VARARGS, curl_getinfo_raw_doc},
    {"pause", (PyCFunction)do_curl_pause, METH_VARARGS, curl_pause_doc},
    {"perform", (PyCFunction)do_curl_perform, METH_NOARGS, curl_perform_doc},
    {"perform_rb", (PyCFunction)do_curl_perform_rb, METH_NOARGS, curl_perform_rb_doc},
    {"perform_rs", (PyCFunction)do_curl_perform_rs, METH_NOARGS, curl_perform_rs_doc},
    {"setopt", (PyCFunction)do_curl_setopt, METH_VARARGS, curl_setopt_doc},
    {"setopt_string", (PyCFunction)do_curl_setopt_string, METH_VARARGS, curl_setopt_string_doc},
    {"unsetopt", (PyCFunction)do_curl_unsetopt, METH_VARARGS, curl_unsetopt_doc},
    {"reset", (PyCFunction)do_curl_reset, METH_NOARGS, curl_reset_doc},
#if defined(HAVE_CURL_OPENSSL)
    {"set_ca_certs", (PyCFunction)do_curl_set_ca_certs, METH_VARARGS, curl_set_ca_certs_doc},
#endif
    {"__getstate__", (PyCFunction)do_curl_getstate, METH_NOARGS, NULL},
    {"__setstate__", (PyCFunction)do_curl_setstate, METH_VARARGS, NULL},
    {NULL, NULL, 0, NULL}
};


/* --------------- setattr/getattr --------------- */


#if PY_MAJOR_VERSION >= 3

PYCURL_INTERNAL PyObject *
do_curl_getattro(PyObject *o, PyObject *n)
{
    PyObject *v = PyObject_GenericGetAttr(o, n);
    if( !v && PyErr_ExceptionMatches(PyExc_AttributeError) )
    {
        PyErr_Clear();
        v = my_getattro(o, n, ((CurlObject *)o)->dict,
                        curlobject_constants, curlobject_methods);
    }
    return v;
}

PYCURL_INTERNAL int
do_curl_setattro(PyObject *o, PyObject *name, PyObject *v)
{
    assert_curl_state((CurlObject *)o);
    return my_setattro(&((CurlObject *)o)->dict, name, v);
}

#else /* PY_MAJOR_VERSION >= 3 */

PYCURL_INTERNAL PyObject *
do_curl_getattr(CurlObject *co, char *name)
{
    assert_curl_state(co);
    return my_getattr((PyObject *)co, name, co->dict,
                      curlobject_constants, curlobject_methods);
}

PYCURL_INTERNAL int
do_curl_setattr(CurlObject *co, char *name, PyObject *v)
{
    assert_curl_state(co);
    return my_setattr(&co->dict, name, v);
}

#endif /* PY_MAJOR_VERSION >= 3 */

PYCURL_INTERNAL PyTypeObject Curl_Type = {
#if PY_MAJOR_VERSION >= 3
    PyVarObject_HEAD_INIT(NULL, 0)
#else
    PyObject_HEAD_INIT(NULL)
    0,                          /* ob_size */
#endif
    "pycurl.Curl",              /* tp_name */
    sizeof(CurlObject),         /* tp_basicsize */
    0,                          /* tp_itemsize */
    (destructor)do_curl_dealloc, /* tp_dealloc */
    0,                          /* tp_print */
#if PY_MAJOR_VERSION >= 3
    0,                          /* tp_getattr */
    0,                          /* tp_setattr */
#else
    (getattrfunc)do_curl_getattr,  /* tp_getattr */
    (setattrfunc)do_curl_setattr,  /* tp_setattr */
#endif
    0,                          /* tp_reserved */
    0,                          /* tp_repr */
    0,                          /* tp_as_number */
    0,                          /* tp_as_sequence */
    0,                          /* tp_as_mapping */
    0,                          /* tp_hash  */
    0,                          /* tp_call */
    0,                          /* tp_str */
#if PY_MAJOR_VERSION >= 3
    (getattrofunc)do_curl_getattro, /* tp_getattro */
    (setattrofunc)do_curl_setattro, /* tp_setattro */
#else
    0,                          /* tp_getattro */
    0,                          /* tp_setattro */
#endif
    0,                          /* tp_as_buffer */
    PYCURL_TYPE_FLAGS,          /* tp_flags */
    curl_doc,                   /* tp_doc */
    (traverseproc)do_curl_traverse, /* tp_traverse */
    (inquiry)do_curl_clear,     /* tp_clear */
    0,                          /* tp_richcompare */
    offsetof(CurlObject, weakreflist), /* tp_weaklistoffset */
    0,                          /* tp_iter */
    0,                          /* tp_iternext */
    curlobject_methods,         /* tp_methods */
    0,                          /* tp_members */
    0,                          /* tp_getset */
    0,                          /* tp_base */
    0,                          /* tp_dict */
    0,                          /* tp_descr_get */
    0,                          /* tp_descr_set */
    0,                          /* tp_dictoffset */
    0,                          /* tp_init */
    PyType_GenericAlloc,        /* tp_alloc */
    (newfunc)do_curl_new,       /* tp_new */
    PyObject_GC_Del,            /* tp_free */
};

/* vi:ts=4:et:nowrap
 */



/* IMPORTANT NOTE: due to threading issues, we cannot call _any_ Python
 * function without acquiring the thread state in the callback handlers.
 */


static size_t
util_write_callback(int flags, char *ptr, size_t size, size_t nmemb, void *stream)
{
    CurlObject *self;
    PyObject *arglist;
    PyObject *result = NULL;
    size_t ret = 0;     /* assume error */
    PyObject *cb;
    int total_size;
    PYCURL_DECLARE_THREAD_STATE;

    /* acquire thread */
    self = (CurlObject *)stream;
    if (!PYCURL_ACQUIRE_THREAD())
        return ret;

    /* check args */
    cb = flags ? self->h_cb : self->w_cb;
    if (cb == NULL)
        goto silent_error;
    if (size <= 0 || nmemb <= 0)
        goto done;
    total_size = (int)(size * nmemb);
    if (total_size < 0 || (size_t)total_size / size != nmemb) {
        PyErr_SetString(ErrorObject, "integer overflow in write callback");
        goto verbose_error;
    }

    /* run callback */
#if PY_MAJOR_VERSION >= 3
    arglist = Py_BuildValue("(y#)", ptr, total_size);
#else
    arglist = Py_BuildValue("(s#)", ptr, total_size);
#endif
    if (arglist == NULL)
        goto verbose_error;
    result = PyEval_CallObject(cb, arglist);
    Py_DECREF(arglist);
    if (result == NULL)
        goto verbose_error;

    /* handle result */
    if (result == Py_None) {
        ret = total_size;           /* None means success */
    }
    else if (PyInt_Check(result) || PyLong_Check(result)) {
        /* if the cast to long fails, PyLong_AsLong() returns -1L */
        ret = (size_t) PyLong_AsLong(result);
    }
    else {
        PyErr_SetString(ErrorObject, "write callback must return int or None");
        goto verbose_error;
    }

done:
silent_error:
    Py_XDECREF(result);
    PYCURL_RELEASE_THREAD();
    return ret;
verbose_error:
    PyErr_Print();
    goto silent_error;
}


PYCURL_INTERNAL size_t
write_callback(char *ptr, size_t size, size_t nmemb, void *stream)
{
    return util_write_callback(0, ptr, size, nmemb, stream);
}

PYCURL_INTERNAL size_t
header_callback(char *ptr, size_t size, size_t nmemb, void *stream)
{
    return util_write_callback(1, ptr, size, nmemb, stream);
}


/* convert protocol address from C to python, returns a tuple of protocol
   specific values */
static PyObject *
convert_protocol_address(struct sockaddr* saddr, unsigned int saddrlen)
{
    PyObject *res_obj = NULL;

    switch (saddr->sa_family)
    {
    case AF_INET:
        {
            struct sockaddr_in* sin = (struct sockaddr_in*)saddr;
            char *addr_str = PyMem_New(char, INET_ADDRSTRLEN);

            if (addr_str == NULL) {
                PyErr_NoMemory();
                goto error;
            }

            if (inet_ntop(saddr->sa_family, &sin->sin_addr, addr_str, INET_ADDRSTRLEN) == NULL) {
                PyErr_SetFromErrno(ErrorObject);
                PyMem_Free(addr_str);
                goto error;
            }
            res_obj = Py_BuildValue("(si)", addr_str, ntohs(sin->sin_port));
            PyMem_Free(addr_str);
       }
        break;
    case AF_INET6:
        {
            struct sockaddr_in6* sin6 = (struct sockaddr_in6*)saddr;
            char *addr_str = PyMem_New(char, INET6_ADDRSTRLEN);

            if (addr_str == NULL) {
                PyErr_NoMemory();
                goto error;
            }

            if (inet_ntop(saddr->sa_family, &sin6->sin6_addr, addr_str, INET6_ADDRSTRLEN) == NULL) {
                PyErr_SetFromErrno(ErrorObject);
                PyMem_Free(addr_str);
                goto error;
            }
            res_obj = Py_BuildValue("(siii)", addr_str, (int) ntohs(sin6->sin6_port),
                (int) ntohl(sin6->sin6_flowinfo), (int) ntohl(sin6->sin6_scope_id));
            PyMem_Free(addr_str);
        }
        break;
#if !defined(WIN32)
    case AF_UNIX:
        {
            struct sockaddr_un* s_un = (struct sockaddr_un*)saddr;

#if PY_MAJOR_VERSION >= 3
            res_obj = Py_BuildValue("y", s_un->sun_path);
#else
            res_obj = Py_BuildValue("s", s_un->sun_path);
#endif
        }
        break;
#endif
    default:
        /* We (currently) only support IPv4/6 addresses.  Can curl even be used
           with anything else? */
        PyErr_SetString(ErrorObject, "Unsupported address family");
    }

error:
    return res_obj;
}


/* curl_socket_t is just an int on unix/windows (with limitations that
 * are not important here) */
PYCURL_INTERNAL curl_socket_t
opensocket_callback(void *clientp, curlsocktype purpose,
                    struct curl_sockaddr *address)
{
    PyObject *arglist;
    PyObject *result = NULL;
    PyObject *fileno_result = NULL;
    CurlObject *self;
    int ret = CURL_SOCKET_BAD;
    PyObject *converted_address;
    PyObject *python_address;
    PYCURL_DECLARE_THREAD_STATE;

    self = (CurlObject *)clientp;
    PYCURL_ACQUIRE_THREAD();

    converted_address = convert_protocol_address(&address->addr, address->addrlen);
    if (converted_address == NULL) {
        goto verbose_error;
    }

    arglist = Py_BuildValue("(iiiN)", address->family, address->socktype, address->protocol, converted_address);
    if (arglist == NULL) {
        Py_DECREF(converted_address);
        goto verbose_error;
    }
    python_address = PyEval_CallObject(curl_sockaddr_type, arglist);
    Py_DECREF(arglist);
    if (python_address == NULL) {
        goto verbose_error;
    }

    arglist = Py_BuildValue("(iN)", purpose, python_address);
    if (arglist == NULL) {
        Py_DECREF(python_address);
        goto verbose_error;
    }
    result = PyEval_CallObject(self->opensocket_cb, arglist);
    Py_DECREF(arglist);
    if (result == NULL) {
        goto verbose_error;
    }

    if (PyInt_Check(result) && PyInt_AsLong(result) == CURL_SOCKET_BAD) {
        ret = CURL_SOCKET_BAD;
    } else if (PyObject_HasAttrString(result, "fileno")) {
        fileno_result = PyObject_CallMethod(result, "fileno", NULL);

        if (fileno_result == NULL) {
            ret = CURL_SOCKET_BAD;
            goto verbose_error;
        }
        // normal operation:
        if (PyInt_Check(fileno_result)) {
            int sockfd = PyInt_AsLong(fileno_result);
#if defined(WIN32)
            ret = dup_winsock(sockfd, address);
#else
            ret = dup(sockfd);
#endif
            goto done;
        } else {
            PyErr_SetString(ErrorObject, "Open socket callback returned an object whose fileno method did not return an integer");
            ret = CURL_SOCKET_BAD;
        }
    } else {
        PyErr_SetString(ErrorObject, "Open socket callback's return value must be a socket");
        ret = CURL_SOCKET_BAD;
        goto verbose_error;
    }

silent_error:
done:
    Py_XDECREF(result);
    Py_XDECREF(fileno_result);
    PYCURL_RELEASE_THREAD();
    return ret;
verbose_error:
    PyErr_Print();
    goto silent_error;
}


PYCURL_INTERNAL int
sockopt_cb(void *clientp, curl_socket_t curlfd, curlsocktype purpose)
{
    PyObject *arglist;
    CurlObject *self;
    int ret = -1;
    PyObject *ret_obj = NULL;
    PYCURL_DECLARE_THREAD_STATE;

    self = (CurlObject *)clientp;
    PYCURL_ACQUIRE_THREAD();

    arglist = Py_BuildValue("(ii)", (int) curlfd, (int) purpose);
    if (arglist == NULL)
        goto verbose_error;

    ret_obj = PyEval_CallObject(self->sockopt_cb, arglist);
    Py_DECREF(arglist);
    if (!PyInt_Check(ret_obj) && !PyLong_Check(ret_obj)) {
        PyObject *ret_repr = PyObject_Repr(ret_obj);
        if (ret_repr) {
            PyObject *encoded_obj;
            char *str = PyText_AsString_NoNUL(ret_repr, &encoded_obj);
            fprintf(stderr, "sockopt callback returned %s which is not an integer\n", str);
            /* PyErr_Format(PyExc_TypeError, "sockopt callback returned %s which is not an integer", str); */
            Py_XDECREF(encoded_obj);
            Py_DECREF(ret_repr);
        }
        goto silent_error;
    }
    if (PyInt_Check(ret_obj)) {
        /* long to int cast */
        ret = (int) PyInt_AsLong(ret_obj);
    } else {
        /* long to int cast */
        ret = (int) PyLong_AsLong(ret_obj);
    }
    goto done;

silent_error:
    ret = -1;
done:
    Py_XDECREF(ret_obj);
    PYCURL_RELEASE_THREAD();
    return ret;
verbose_error:
    PyErr_Print();
    goto silent_error;
}


#if LIBCURL_VERSION_NUM >= MAKE_LIBCURL_VERSION(7, 21, 7)
PYCURL_INTERNAL int
closesocket_callback(void *clientp, curl_socket_t curlfd)
{
    PyObject *arglist;
    CurlObject *self;
    int ret = -1;
    PyObject *ret_obj = NULL;
    PYCURL_DECLARE_THREAD_STATE;

    self = (CurlObject *)clientp;
    PYCURL_ACQUIRE_THREAD();

    arglist = Py_BuildValue("(i)", (int) curlfd);
    if (arglist == NULL)
        goto verbose_error;

    ret_obj = PyEval_CallObject(self->closesocket_cb, arglist);
    Py_DECREF(arglist);
    if (!ret_obj)
       goto silent_error;
    if (!PyInt_Check(ret_obj) && !PyLong_Check(ret_obj)) {
        PyObject *ret_repr = PyObject_Repr(ret_obj);
        if (ret_repr) {
            PyObject *encoded_obj;
            char *str = PyText_AsString_NoNUL(ret_repr, &encoded_obj);
            fprintf(stderr, "closesocket callback returned %s which is not an integer\n", str);
            /* PyErr_Format(PyExc_TypeError, "closesocket callback returned %s which is not an integer", str); */
            Py_XDECREF(encoded_obj);
            Py_DECREF(ret_repr);
        }
        goto silent_error;
    }
    if (PyInt_Check(ret_obj)) {
        /* long to int cast */
        ret = (int) PyInt_AsLong(ret_obj);
    } else {
        /* long to int cast */
        ret = (int) PyLong_AsLong(ret_obj);
    }
    goto done;

silent_error:
    ret = -1;
done:
    Py_XDECREF(ret_obj);
    PYCURL_RELEASE_THREAD();
    return ret;
verbose_error:
    PyErr_Print();
    goto silent_error;
}
#endif


#ifdef HAVE_CURL_7_19_6_OPTS
static PyObject *
khkey_to_object(const struct curl_khkey *khkey)
{
    PyObject *arglist, *ret;

    if (khkey == NULL) {
        Py_INCREF(Py_None);
        return Py_None;
    }

    if (khkey->len) {
#if PY_MAJOR_VERSION >= 3
        arglist = Py_BuildValue("(y#i)", khkey->key, khkey->len, khkey->keytype);
#else
        arglist = Py_BuildValue("(s#i)", khkey->key, khkey->len, khkey->keytype);
#endif
    } else {
#if PY_MAJOR_VERSION >= 3
        arglist = Py_BuildValue("(yi)", khkey->key, khkey->keytype);
#else
        arglist = Py_BuildValue("(si)", khkey->key, khkey->keytype);
#endif
    }

    if (arglist == NULL) {
        return NULL;
    }

    ret = PyObject_Call(khkey_type, arglist, NULL);
    Py_DECREF(arglist);
    return ret;
}


PYCURL_INTERNAL int
ssh_key_cb(CURL *easy, const struct curl_khkey *knownkey,
    const struct curl_khkey *foundkey, int khmatch, void *clientp)
{
    PyObject *arglist;
    CurlObject *self;
    int ret = -1;
    PyObject *knownkey_obj = NULL;
    PyObject *foundkey_obj = NULL;
    PyObject *ret_obj = NULL;
    PYCURL_DECLARE_THREAD_STATE;

    self = (CurlObject *)clientp;
    PYCURL_ACQUIRE_THREAD();

    knownkey_obj = khkey_to_object(knownkey);
    if (knownkey_obj == NULL) {
        goto silent_error;
    }
    foundkey_obj = khkey_to_object(foundkey);
    if (foundkey_obj == NULL) {
        goto silent_error;
    }

    arglist = Py_BuildValue("(OOi)", knownkey_obj, foundkey_obj, khmatch);
    if (arglist == NULL)
        goto verbose_error;

    ret_obj = PyEval_CallObject(self->ssh_key_cb, arglist);
    Py_DECREF(arglist);
    if (!PyInt_Check(ret_obj) && !PyLong_Check(ret_obj)) {
        PyObject *ret_repr = PyObject_Repr(ret_obj);
        if (ret_repr) {
            PyObject *encoded_obj;
            char *str = PyText_AsString_NoNUL(ret_repr, &encoded_obj);
            fprintf(stderr, "ssh key callback returned %s which is not an integer\n", str);
            /* PyErr_Format(PyExc_TypeError, "ssh key callback returned %s which is not an integer", str); */
            Py_XDECREF(encoded_obj);
            Py_DECREF(ret_repr);
        }
        goto silent_error;
    }
    if (PyInt_Check(ret_obj)) {
        /* long to int cast */
        ret = (int) PyInt_AsLong(ret_obj);
    } else {
        /* long to int cast */
        ret = (int) PyLong_AsLong(ret_obj);
    }
    goto done;

silent_error:
    ret = -1;
done:
    Py_XDECREF(knownkey_obj);
    Py_XDECREF(foundkey_obj);
    Py_XDECREF(ret_obj);
    PYCURL_RELEASE_THREAD();
    return ret;
verbose_error:
    PyErr_Print();
    goto silent_error;
}
#endif


PYCURL_INTERNAL int
seek_callback(void *stream, curl_off_t offset, int origin)
{
    CurlObject *self;
    PyObject *arglist;
    PyObject *result = NULL;
    int ret = 2;     /* assume error 2 (can't seek, libcurl free to work around). */
    PyObject *cb;
    int source = 0;     /* assume beginning */
    PYCURL_DECLARE_THREAD_STATE;

    /* acquire thread */
    self = (CurlObject *)stream;
    if (!PYCURL_ACQUIRE_THREAD())
        return ret;

    /* check arguments */
    switch (origin)
    {
      case SEEK_SET:
          source = 0;
          break;
      case SEEK_CUR:
          source = 1;
          break;
      case SEEK_END:
          source = 2;
          break;
      default:
          source = origin;
          break;
    }

    /* run callback */
    cb = self->seek_cb;
    if (cb == NULL)
        goto silent_error;
    arglist = Py_BuildValue("(i,i)", offset, source);
    if (arglist == NULL)
        goto verbose_error;
    result = PyEval_CallObject(cb, arglist);
    Py_DECREF(arglist);
    if (result == NULL)
        goto verbose_error;

    /* handle result */
    if (result == Py_None) {
        ret = 0;           /* None means success */
    }
    else if (PyInt_Check(result)) {
        int ret_code = PyInt_AsLong(result);
        if (ret_code < 0 || ret_code > 2) {
            PyErr_Format(ErrorObject, "invalid return value for seek callback %d not in (0, 1, 2)", ret_code);
            goto verbose_error;
        }
        ret = ret_code;    /* pass the return code from the callback */
    }
    else {
        PyErr_SetString(ErrorObject, "seek callback must return 0 (CURL_SEEKFUNC_OK), 1 (CURL_SEEKFUNC_FAIL), 2 (CURL_SEEKFUNC_CANTSEEK) or None");
        goto verbose_error;
    }

silent_error:
    Py_XDECREF(result);
    PYCURL_RELEASE_THREAD();
    return ret;
verbose_error:
    PyErr_Print();
    goto silent_error;
}




PYCURL_INTERNAL size_t
read_callback(char *ptr, size_t size, size_t nmemb, void *stream)
{
    CurlObject *self;
    PyObject *arglist;
    PyObject *result = NULL;

    size_t ret = CURL_READFUNC_ABORT;     /* assume error, this actually works */
    int total_size;

    PYCURL_DECLARE_THREAD_STATE;

    /* acquire thread */
    self = (CurlObject *)stream;
    if (!PYCURL_ACQUIRE_THREAD())
        return ret;

    /* check args */
    if (self->r_cb == NULL)
        goto silent_error;
    if (size <= 0 || nmemb <= 0)
        goto done;
    total_size = (int)(size * nmemb);
    if (total_size < 0 || (size_t)total_size / size != nmemb) {
        PyErr_SetString(ErrorObject, "integer overflow in read callback");
        goto verbose_error;
    }

    /* run callback */
    arglist = Py_BuildValue("(i)", total_size);
    if (arglist == NULL)
        goto verbose_error;
    result = PyEval_CallObject(self->r_cb, arglist);
    Py_DECREF(arglist);
    if (result == NULL)
        goto verbose_error;

    /* handle result */
    if (PyByteStr_Check(result)) {
        char *buf = NULL;
        Py_ssize_t obj_size = -1;
        Py_ssize_t r;
        r = PyByteStr_AsStringAndSize(result, &buf, &obj_size);
        if (r != 0 || obj_size < 0 || obj_size > total_size) {
            PyErr_Format(ErrorObject, "invalid return value for read callback (%ld bytes returned when at most %ld bytes were wanted)", (long)obj_size, (long)total_size);
            goto verbose_error;
        }
        memcpy(ptr, buf, obj_size);
        ret = obj_size;             /* success */
    }
    else if (PyUnicode_Check(result)) {
        char *buf = NULL;
        Py_ssize_t obj_size = -1;
        Py_ssize_t r;
        /*
        Encode with ascii codec.

        HTTP requires sending content-length for request body to the server
        before the request body is sent, therefore typically content length
        is given via POSTFIELDSIZE before read function is invoked to
        provide the data.

        However, if we encode the string using any encoding other than ascii,
        the length of encoded string may not match the length of unicode
        string we are encoding. Therefore, if client code does a simple
        len(source_string) to determine the value to supply in content-length,
        the length of bytes read may be different.

        To avoid this situation, we only accept ascii bytes in the string here.

        Encode data yourself to bytes when dealing with non-ascii data.
        */
        PyObject *encoded = PyUnicode_AsEncodedString(result, "ascii", "strict");
        if (encoded == NULL) {
            goto verbose_error;
        }
        r = PyByteStr_AsStringAndSize(encoded, &buf, &obj_size);
        if (r != 0 || obj_size < 0 || obj_size > total_size) {
            Py_DECREF(encoded);
            PyErr_Format(ErrorObject, "invalid return value for read callback (%ld bytes returned after encoding to utf-8 when at most %ld bytes were wanted)", (long)obj_size, (long)total_size);
            goto verbose_error;
        }
        memcpy(ptr, buf, obj_size);
        Py_DECREF(encoded);
        ret = obj_size;             /* success */
    }
#if PY_MAJOR_VERSION < 3
    else if (PyInt_Check(result)) {
        long r = PyInt_AsLong(result);
        if (r != CURL_READFUNC_ABORT && r != CURL_READFUNC_PAUSE)
            goto type_error;
        ret = r; /* either CURL_READFUNC_ABORT or CURL_READFUNC_PAUSE */
    }
#endif
    else if (PyLong_Check(result)) {
        long r = PyLong_AsLong(result);
        if (r != CURL_READFUNC_ABORT && r != CURL_READFUNC_PAUSE)
            goto type_error;
        ret = r; /* either CURL_READFUNC_ABORT or CURL_READFUNC_PAUSE */
    }
    else {
    type_error:
        PyErr_SetString(ErrorObject, "read callback must return a byte string or Unicode string with ASCII code points only");
        goto verbose_error;
    }

done:
silent_error:
    Py_XDECREF(result);
    PYCURL_RELEASE_THREAD();
    return ret;
verbose_error:
    PyErr_Print();
    goto silent_error;
}


PYCURL_INTERNAL int
progress_callback(void *stream,
                  double dltotal, double dlnow, double ultotal, double ulnow)
{
    CurlObject *self;
    PyObject *arglist;
    PyObject *result = NULL;
    int ret = 1;       /* assume error */
    PYCURL_DECLARE_THREAD_STATE;

    /* acquire thread */
    self = (CurlObject *)stream;
    if (!PYCURL_ACQUIRE_THREAD())
        return ret;

    /* check args */
    if (self->pro_cb == NULL)
        goto silent_error;

    /* run callback */
    arglist = Py_BuildValue("(dddd)", dltotal, dlnow, ultotal, ulnow);
    if (arglist == NULL)
        goto verbose_error;
    result = PyEval_CallObject(self->pro_cb, arglist);
    Py_DECREF(arglist);
    if (result == NULL)
        goto verbose_error;

    /* handle result */
    if (result == Py_None) {
        ret = 0;        /* None means success */
    }
    else if (PyInt_Check(result)) {
        ret = (int) PyInt_AsLong(result);
    }
    else {
        ret = PyObject_IsTrue(result);  /* FIXME ??? */
    }

silent_error:
    Py_XDECREF(result);
    PYCURL_RELEASE_THREAD();
    return ret;
verbose_error:
    PyErr_Print();
    goto silent_error;
}


#if LIBCURL_VERSION_NUM >= MAKE_LIBCURL_VERSION(7, 32, 0)
PYCURL_INTERNAL int
xferinfo_callback(void *stream,
    curl_off_t dltotal, curl_off_t dlnow,
    curl_off_t ultotal, curl_off_t ulnow)
{
    CurlObject *self;
    PyObject *arglist;
    PyObject *result = NULL;
    int ret = 1;       /* assume error */
    PYCURL_DECLARE_THREAD_STATE;

    /* acquire thread */
    self = (CurlObject *)stream;
    if (!PYCURL_ACQUIRE_THREAD())
        return ret;

    /* check args */
    if (self->xferinfo_cb == NULL)
        goto silent_error;

    /* run callback */
    arglist = Py_BuildValue("(LLLL)",
        (PY_LONG_LONG) dltotal, (PY_LONG_LONG) dlnow,
        (PY_LONG_LONG) ultotal, (PY_LONG_LONG) ulnow);
    if (arglist == NULL)
        goto verbose_error;
    result = PyEval_CallObject(self->xferinfo_cb, arglist);
    Py_DECREF(arglist);
    if (result == NULL)
        goto verbose_error;

    /* handle result */
    if (result == Py_None) {
        ret = 0;        /* None means success */
    }
    else if (PyInt_Check(result)) {
        ret = (int) PyInt_AsLong(result);
    }
    else {
        ret = PyObject_IsTrue(result);  /* FIXME ??? */
    }

silent_error:
    Py_XDECREF(result);
    PYCURL_RELEASE_THREAD();
    return ret;
verbose_error:
    PyErr_Print();
    goto silent_error;
}
#endif


PYCURL_INTERNAL int
debug_callback(CURL *curlobj, curl_infotype type,
               char *buffer, size_t total_size, void *stream)
{
    CurlObject *self;
    PyObject *arglist;
    PyObject *result = NULL;
    int ret = 0;       /* always success */
    PYCURL_DECLARE_THREAD_STATE;

    UNUSED(curlobj);

    /* acquire thread */
    self = (CurlObject *)stream;
    if (!PYCURL_ACQUIRE_THREAD())
        return ret;

    /* check args */
    if (self->debug_cb == NULL)
        goto silent_error;
    if ((int)total_size < 0 || (size_t)((int)total_size) != total_size) {
        PyErr_SetString(ErrorObject, "integer overflow in debug callback");
        goto verbose_error;
    }

    /* run callback */
#if PY_MAJOR_VERSION >= 3
    arglist = Py_BuildValue("(iy#)", (int)type, buffer, (int)total_size);
#else
    arglist = Py_BuildValue("(is#)", (int)type, buffer, (int)total_size);
#endif
    if (arglist == NULL)
        goto verbose_error;
    result = PyEval_CallObject(self->debug_cb, arglist);
    Py_DECREF(arglist);
    if (result == NULL)
        goto verbose_error;

    /* return values from debug callbacks should be ignored */

silent_error:
    Py_XDECREF(result);
    PYCURL_RELEASE_THREAD();
    return ret;
verbose_error:
    PyErr_Print();
    goto silent_error;
}


PYCURL_INTERNAL curlioerr
ioctl_callback(CURL *curlobj, int cmd, void *stream)
{
    CurlObject *self;
    PyObject *arglist;
    PyObject *result = NULL;
    int ret = CURLIOE_FAILRESTART;       /* assume error */
    PYCURL_DECLARE_THREAD_STATE;

    UNUSED(curlobj);

    /* acquire thread */
    self = (CurlObject *)stream;
    if (!PYCURL_ACQUIRE_THREAD())
        return (curlioerr) ret;

    /* check args */
    if (self->ioctl_cb == NULL)
        goto silent_error;

    /* run callback */
    arglist = Py_BuildValue("(i)", cmd);
    if (arglist == NULL)
        goto verbose_error;
    result = PyEval_CallObject(self->ioctl_cb, arglist);
    Py_DECREF(arglist);
    if (result == NULL)
        goto verbose_error;

    /* handle result */
    if (result == Py_None) {
        ret = CURLIOE_OK;        /* None means success */
    }
    else if (PyInt_Check(result)) {
        ret = (int) PyInt_AsLong(result);
        if (ret >= CURLIOE_LAST || ret < 0) {
            PyErr_SetString(ErrorObject, "ioctl callback returned invalid value");
            goto verbose_error;
        }
    }

silent_error:
    Py_XDECREF(result);
    PYCURL_RELEASE_THREAD();
    return (curlioerr) ret;
verbose_error:
    PyErr_Print();
    goto silent_error;
}


#if defined(HAVE_CURL_OPENSSL)
/* internal helper that load certificates from buffer, returns -1 on error  */
static int
add_ca_certs(SSL_CTX *context, void *data, Py_ssize_t len)
{
    // this code was copied from _ssl module
    BIO *biobuf = NULL;
    X509_STORE *store;
    int retval = 0, err, loaded = 0;

    if (len <= 0) {
        PyErr_SetString(PyExc_ValueError,
                        "Empty certificate data");
        return -1;
    } else if (len > INT_MAX) {
        PyErr_SetString(PyExc_OverflowError,
                        "Certificate data is too long.");
        return -1;
    }

    biobuf = BIO_new_mem_buf(data, (int)len);
    if (biobuf == NULL) {
        PyErr_SetString(PyExc_MemoryError, "Can't allocate buffer");
        ERR_clear_error();
        return -1;
    }

    store = SSL_CTX_get_cert_store(context);
    assert(store != NULL);

    while (1) {
        X509 *cert = NULL;
        int r;

        cert = PEM_read_bio_X509(biobuf, NULL, 0, NULL);
        if (cert == NULL) {
            break;
        }
        r = X509_STORE_add_cert(store, cert);
        X509_free(cert);
        if (!r) {
            err = ERR_peek_last_error();
            if ((ERR_GET_LIB(err) == ERR_LIB_X509) &&
                (ERR_GET_REASON(err) == X509_R_CERT_ALREADY_IN_HASH_TABLE)) {
                /* cert already in hash table, not an error */
                ERR_clear_error();
            } else {
                break;
            }
        }
        loaded++;
    }

    err = ERR_peek_last_error();
    if ((loaded > 0) &&
            (ERR_GET_LIB(err) == ERR_LIB_PEM) &&
            (ERR_GET_REASON(err) == PEM_R_NO_START_LINE)) {
        /* EOF PEM file, not an error */
        ERR_clear_error();
        retval = 0;
    } else {
        PyErr_SetString(ErrorObject, ERR_reason_error_string(err));
        ERR_clear_error();
        retval = -1;
    }

    BIO_free(biobuf);
    return retval;
}


PYCURL_INTERNAL CURLcode
ssl_ctx_callback(CURL *curl, void *ssl_ctx, void *ptr)
{
    CurlObject *self;
    PYCURL_DECLARE_THREAD_STATE;
    int r;

    UNUSED(curl);

    /* acquire thread */
    self = (CurlObject *)ptr;
    if (!PYCURL_ACQUIRE_THREAD())
        return CURLE_FAILED_INIT;

    r = add_ca_certs((SSL_CTX*)ssl_ctx,
                         PyBytes_AS_STRING(self->ca_certs_obj),
                         PyBytes_GET_SIZE(self->ca_certs_obj));

    if (r != 0)
        PyErr_Print();

    PYCURL_RELEASE_THREAD();
    return r == 0 ? CURLE_OK : CURLE_FAILED_INIT;
}
#endif



/* Convert a curl slist (a list of strings) to a Python list.
 * In case of error return NULL with an exception set.
 */
static PyObject *convert_slist(struct curl_slist *slist, int free_flags)
{
    PyObject *ret = NULL;
    struct curl_slist *slist_start = slist;

    ret = PyList_New((Py_ssize_t)0);
    if (ret == NULL) goto error;

    for ( ; slist != NULL; slist = slist->next) {
        PyObject *v = NULL;

        if (slist->data == NULL) {
            v = Py_None; Py_INCREF(v);
        } else {
            v = PyByteStr_FromString(slist->data);
        }
        if (v == NULL || PyList_Append(ret, v) != 0) {
            Py_XDECREF(v);
            goto error;
        }
        Py_DECREF(v);
    }

    if ((free_flags & 1) && slist_start)
        curl_slist_free_all(slist_start);
    return ret;

error:
    Py_XDECREF(ret);
    if ((free_flags & 2) && slist_start)
        curl_slist_free_all(slist_start);
    return NULL;
}


#ifdef HAVE_CURLOPT_CERTINFO
/* Convert a struct curl_certinfo into a Python data structure.
 * In case of error return NULL with an exception set.
 */
static PyObject *convert_certinfo(struct curl_certinfo *cinfo, int decode)
{
    PyObject *certs;
    int cert_index;

    if (!cinfo)
        Py_RETURN_NONE;

    certs = PyList_New((Py_ssize_t)(cinfo->num_of_certs));
    if (!certs)
        return NULL;

    for (cert_index = 0; cert_index < cinfo->num_of_certs; cert_index ++) {
        struct curl_slist *fields = cinfo->certinfo[cert_index];
        struct curl_slist *field_cursor;
        int field_count, field_index;
        PyObject *cert;

        field_count = 0;
        field_cursor = fields;
        while (field_cursor != NULL) {
            field_cursor = field_cursor->next;
            field_count ++;
        }


        cert = PyTuple_New((Py_ssize_t)field_count);
        if (!cert)
            goto error;
        PyList_SetItem(certs, cert_index, cert); /* Eats the ref from New() */

        for(field_index = 0, field_cursor = fields;
            field_cursor != NULL;
            field_index ++, field_cursor = field_cursor->next) {
            const char *field = field_cursor->data;
            PyObject *field_tuple;

            if (!field) {
                field_tuple = Py_None; Py_INCREF(field_tuple);
            } else {
                const char *sep = strchr(field, ':');
                if (!sep) {
                    if (decode) {
                        field_tuple = PyText_FromString(field);
                    } else {
                        field_tuple = PyByteStr_FromString(field);
                    }
                } else {
                    /* XXX check */
                    if (decode) {
                        field_tuple = Py_BuildValue("s#s", field, (int)(sep - field), sep+1);
                    } else {
#if PY_MAJOR_VERSION >= 3
                        field_tuple = Py_BuildValue("y#y", field, (int)(sep - field), sep+1);
#else
                        field_tuple = Py_BuildValue("s#s", field, (int)(sep - field), sep+1);
#endif
                    }
                }
                if (!field_tuple)
                    goto error;
            }
            PyTuple_SET_ITEM(cert, field_index, field_tuple); /* Eats the ref */
        }
    }

    return certs;

 error:
    Py_DECREF(certs);
    return NULL;
}
#endif

PYCURL_INTERNAL PyObject *
do_curl_getinfo_raw(CurlObject *self, PyObject *args)
{
    int option;
    int res;

    if (!PyArg_ParseTuple(args, "i:getinfo_raw", &option)) {
        return NULL;
    }
    if (check_curl_state(self, 1 | 2, "getinfo") != 0) {
        return NULL;
    }

    switch (option) {
    case CURLINFO_FILETIME:
    case CURLINFO_HEADER_SIZE:
    case CURLINFO_RESPONSE_CODE:
    case CURLINFO_REDIRECT_COUNT:
    case CURLINFO_REQUEST_SIZE:
    case CURLINFO_SSL_VERIFYRESULT:
    case CURLINFO_HTTP_CONNECTCODE:
    case CURLINFO_HTTPAUTH_AVAIL:
    case CURLINFO_PROXYAUTH_AVAIL:
    case CURLINFO_OS_ERRNO:
    case CURLINFO_NUM_CONNECTS:
    case CURLINFO_LASTSOCKET:
#ifdef HAVE_CURLINFO_LOCAL_PORT
    case CURLINFO_LOCAL_PORT:
#endif
#ifdef HAVE_CURLINFO_PRIMARY_PORT
    case CURLINFO_PRIMARY_PORT:
#endif
#if LIBCURL_VERSION_NUM >= MAKE_LIBCURL_VERSION(7, 20, 0)
    case CURLINFO_RTSP_CLIENT_CSEQ:
    case CURLINFO_RTSP_SERVER_CSEQ:
    case CURLINFO_RTSP_CSEQ_RECV:
#endif
#ifdef HAVE_CURLINFO_HTTP_VERSION
    case CURLINFO_HTTP_VERSION:
#endif

        {
            /* Return PyInt as result */
            long l_res = -1;

            res = curl_easy_getinfo(self->handle, (CURLINFO)option, &l_res);
            /* Check for errors and return result */
            if (res != CURLE_OK) {
                CURLERROR_RETVAL();
            }
            return PyInt_FromLong(l_res);
        }

    case CURLINFO_CONTENT_TYPE:
    case CURLINFO_EFFECTIVE_URL:
    case CURLINFO_FTP_ENTRY_PATH:
    case CURLINFO_REDIRECT_URL:
    case CURLINFO_PRIMARY_IP:
#ifdef HAVE_CURLINFO_LOCAL_IP
    case CURLINFO_LOCAL_IP:
#endif
#if LIBCURL_VERSION_NUM >= MAKE_LIBCURL_VERSION(7, 20, 0)
    case CURLINFO_RTSP_SESSION_ID:
#endif
        {
            /* Return PyString as result */
            char *s_res = NULL;

            res = curl_easy_getinfo(self->handle, (CURLINFO)option, &s_res);
            if (res != CURLE_OK) {
                CURLERROR_RETVAL();
            }
            /* If the resulting string is NULL, return None */
            if (s_res == NULL) {
                Py_RETURN_NONE;
            }
            return PyByteStr_FromString(s_res);

        }

    case CURLINFO_CONNECT_TIME:
    case CURLINFO_APPCONNECT_TIME:
    case CURLINFO_CONTENT_LENGTH_DOWNLOAD:
    case CURLINFO_CONTENT_LENGTH_UPLOAD:
    case CURLINFO_NAMELOOKUP_TIME:
    case CURLINFO_PRETRANSFER_TIME:
    case CURLINFO_REDIRECT_TIME:
    case CURLINFO_SIZE_DOWNLOAD:
    case CURLINFO_SIZE_UPLOAD:
    case CURLINFO_SPEED_DOWNLOAD:
    case CURLINFO_SPEED_UPLOAD:
    case CURLINFO_STARTTRANSFER_TIME:
    case CURLINFO_TOTAL_TIME:
        {
            /* Return PyFloat as result */
            double d_res = 0.0;

            res = curl_easy_getinfo(self->handle, (CURLINFO)option, &d_res);
            if (res != CURLE_OK) {
                CURLERROR_RETVAL();
            }
            return PyFloat_FromDouble(d_res);
        }

    case CURLINFO_SSL_ENGINES:
    case CURLINFO_COOKIELIST:
        {
            /* Return a list of strings */
            struct curl_slist *slist = NULL;

            res = curl_easy_getinfo(self->handle, (CURLINFO)option, &slist);
            if (res != CURLE_OK) {
                CURLERROR_RETVAL();
            }
            return convert_slist(slist, 1 | 2);
        }

#ifdef HAVE_CURLOPT_CERTINFO
    case CURLINFO_CERTINFO:
        {
            /* Return a list of lists of 2-tuples */
            struct curl_certinfo *clist = NULL;
            res = curl_easy_getinfo(self->handle, CURLINFO_CERTINFO, &clist);
            if (res != CURLE_OK) {
                CURLERROR_RETVAL();
            } else {
                return convert_certinfo(clist, 0);
            }
        }
#endif
    }

    /* Got wrong option on the method call */
    PyErr_SetString(PyExc_ValueError, "invalid argument to getinfo");
    return NULL;
}


#if PY_MAJOR_VERSION >= 3
static PyObject *
decode_string_list(PyObject *list)
{
    PyObject *decoded_list = NULL;
    Py_ssize_t size = PyList_Size(list);
    int i;
    
    decoded_list = PyList_New(size);
    if (decoded_list == NULL) {
        return NULL;
    }
    
    for (i = 0; i < size; ++i) {
        PyObject *decoded_item = PyUnicode_FromEncodedObject(
            PyList_GET_ITEM(list, i),
            NULL,
            NULL);
        
        if (decoded_item == NULL) {
            goto err;
        }
	PyList_SetItem(decoded_list, i, decoded_item);
    }
    
    return decoded_list;
    
err:
    Py_DECREF(decoded_list);
    return NULL;
}

PYCURL_INTERNAL PyObject *
do_curl_getinfo(CurlObject *self, PyObject *args)
{
    int option, res;
    PyObject *rv;

    if (!PyArg_ParseTuple(args, "i:getinfo", &option)) {
        return NULL;
    }
    
#ifdef HAVE_CURLOPT_CERTINFO
    if (option == CURLINFO_CERTINFO) {
        /* Return a list of lists of 2-tuples */
        struct curl_certinfo *clist = NULL;
        res = curl_easy_getinfo(self->handle, CURLINFO_CERTINFO, &clist);
        if (res != CURLE_OK) {
            CURLERROR_RETVAL();
        } else {
            return convert_certinfo(clist, 1);
        }
    }
#endif
    
    rv = do_curl_getinfo_raw(self, args);
    if (rv == NULL) {
        return rv;
    }
    
    switch (option) {
    case CURLINFO_CONTENT_TYPE:
    case CURLINFO_EFFECTIVE_URL:
    case CURLINFO_FTP_ENTRY_PATH:
    case CURLINFO_REDIRECT_URL:
    case CURLINFO_PRIMARY_IP:
#ifdef HAVE_CURLINFO_LOCAL_IP
    case CURLINFO_LOCAL_IP:
#endif
#if LIBCURL_VERSION_NUM >= MAKE_LIBCURL_VERSION(7, 20, 0)
    case CURLINFO_RTSP_SESSION_ID:
#endif
        {
            PyObject *decoded;
            
            // Decode bytes into a Unicode string using default encoding
            decoded = PyUnicode_FromEncodedObject(rv, NULL, NULL);
            // success and failure paths both need to free bytes object
            Py_DECREF(rv);
            return decoded;
        }

    case CURLINFO_SSL_ENGINES:
    case CURLINFO_COOKIELIST:
        {
            PyObject *decoded = decode_string_list(rv);
            Py_DECREF(rv);
            return decoded;
        }
        
    default:
        return rv;
    }
}
#endif


PYCURL_INTERNAL PyObject *
do_curl_errstr(CurlObject *self)
{
    if (check_curl_state(self, 1 | 2, "errstr") != 0) {
        return NULL;
    }
    self->error[sizeof(self->error) - 1] = 0;

    return PyText_FromString(self->error);
}


#if PY_MAJOR_VERSION >= 3
PYCURL_INTERNAL PyObject *
do_curl_errstr_raw(CurlObject *self)
{
    if (check_curl_state(self, 1 | 2, "errstr") != 0) {
        return NULL;
    }
    self->error[sizeof(self->error) - 1] = 0;

    return PyByteStr_FromString(self->error);
}
#endif



static struct curl_slist *
pycurl_list_or_tuple_to_slist(int which, PyObject *obj, Py_ssize_t len)
{
    struct curl_slist *slist = NULL;
    Py_ssize_t i;

    for (i = 0; i < len; i++) {
        PyObject *listitem = PyListOrTuple_GetItem(obj, i, which);
        struct curl_slist *nlist;
        char *str;
        PyObject *sencoded_obj;

        if (!PyText_Check(listitem)) {
            curl_slist_free_all(slist);
            PyErr_SetString(PyExc_TypeError, "list items must be byte strings or Unicode strings with ASCII code points only");
            return NULL;
        }
        /* INFO: curl_slist_append() internally does strdup() the data, so
         * no embedded NUL characters allowed here. */
        str = PyText_AsString_NoNUL(listitem, &sencoded_obj);
        if (str == NULL) {
            curl_slist_free_all(slist);
            return NULL;
        }
        nlist = curl_slist_append(slist, str);
        PyText_EncodedDecref(sencoded_obj);
        if (nlist == NULL || nlist->data == NULL) {
            curl_slist_free_all(slist);
            PyErr_NoMemory();
            return NULL;
        }
        slist = nlist;
    }
    return slist;
}


static PyObject *
util_curl_unsetopt(CurlObject *self, int option)
{
    int res;

#define SETOPT2(o,x) \
    if ((res = curl_easy_setopt(self->handle, (o), (x))) != CURLE_OK) goto error
#define SETOPT(x)   SETOPT2((CURLoption)option, (x))
#define CLEAR_CALLBACK(callback_option, data_option, callback_field) \
    case callback_option: \
        if ((res = curl_easy_setopt(self->handle, callback_option, NULL)) != CURLE_OK) \
            goto error; \
        if ((res = curl_easy_setopt(self->handle, data_option, NULL)) != CURLE_OK) \
            goto error; \
        Py_CLEAR(callback_field); \
        break

    /* FIXME: implement more options. Have to carefully check lib/url.c in the
     *   libcurl source code to see if it's actually safe to simply
     *   unset the option. */
    switch (option)
    {
    case CURLOPT_SHARE:
        SETOPT((CURLSH *) NULL);
        Py_XDECREF(self->share);
        self->share = NULL;
        break;
    case CURLOPT_HTTPPOST:
        SETOPT((void *) 0);
        curl_formfree(self->httppost);
        util_curl_xdecref(self, PYCURL_MEMGROUP_HTTPPOST, self->handle);
        self->httppost = NULL;
        /* FIXME: what about data->set.httpreq ?? */
        break;
    case CURLOPT_INFILESIZE:
        SETOPT((long) -1);
        break;
    case CURLOPT_WRITEHEADER:
        SETOPT((void *) 0);
        Py_CLEAR(self->writeheader_fp);
        break;
    case CURLOPT_CAINFO:
    case CURLOPT_CAPATH:
    case CURLOPT_COOKIE:
    case CURLOPT_COOKIEJAR:
    case CURLOPT_CUSTOMREQUEST:
    case CURLOPT_EGDSOCKET:
    case CURLOPT_ENCODING:
    case CURLOPT_FTPPORT:
    case CURLOPT_PROXYUSERPWD:
#ifdef HAVE_CURLOPT_PROXYUSERNAME
    case CURLOPT_PROXYUSERNAME:
    case CURLOPT_PROXYPASSWORD:
#endif
    case CURLOPT_RANDOM_FILE:
    case CURLOPT_SSL_CIPHER_LIST:
    case CURLOPT_USERPWD:
#ifdef HAVE_CURLOPT_USERNAME
    case CURLOPT_USERNAME:
    case CURLOPT_PASSWORD:
#endif
    case CURLOPT_RANGE:
#if LIBCURL_VERSION_NUM >= MAKE_LIBCURL_VERSION(7, 43, 0)
    case CURLOPT_SERVICE_NAME:
    case CURLOPT_PROXY_SERVICE_NAME:
#endif
    case CURLOPT_HTTPHEADER:
#if LIBCURL_VERSION_NUM >= MAKE_LIBCURL_VERSION(7, 37, 0)
    case CURLOPT_PROXYHEADER:
#endif
#if LIBCURL_VERSION_NUM >= MAKE_LIBCURL_VERSION(7, 52, 0)
    case CURLOPT_PROXY_CAPATH:
    case CURLOPT_PROXY_CAINFO:
    case CURLOPT_PRE_PROXY:
    case CURLOPT_PROXY_SSLCERT:
    case CURLOPT_PROXY_SSLCERTTYPE:
    case CURLOPT_PROXY_SSLKEY:
    case CURLOPT_PROXY_SSLKEYTYPE:
#endif
        SETOPT((char *) NULL);
        break;

#ifdef HAVE_CURLOPT_CERTINFO
    case CURLOPT_CERTINFO:
        SETOPT((long) 0);
        break;
#endif

    CLEAR_CALLBACK(CURLOPT_OPENSOCKETFUNCTION, CURLOPT_OPENSOCKETDATA, self->opensocket_cb);
#if LIBCURL_VERSION_NUM >= MAKE_LIBCURL_VERSION(7, 21, 7)
    CLEAR_CALLBACK(CURLOPT_CLOSESOCKETFUNCTION, CURLOPT_CLOSESOCKETDATA, self->closesocket_cb);
#endif
    CLEAR_CALLBACK(CURLOPT_SOCKOPTFUNCTION, CURLOPT_SOCKOPTDATA, self->sockopt_cb);
#ifdef HAVE_CURL_7_19_6_OPTS
    CLEAR_CALLBACK(CURLOPT_SSH_KEYFUNCTION, CURLOPT_SSH_KEYDATA, self->ssh_key_cb);
#endif

    /* info: we explicitly list unsupported options here */
    case CURLOPT_COOKIEFILE:
    default:
        PyErr_SetString(PyExc_TypeError, "unsetopt() is not supported for this option");
        return NULL;
    }

    Py_RETURN_NONE;

error:
    CURLERROR_RETVAL();

#undef SETOPT
#undef SETOPT2
#undef CLEAR_CALLBACK
}


PYCURL_INTERNAL PyObject *
do_curl_unsetopt(CurlObject *self, PyObject *args)
{
    int option;

    if (!PyArg_ParseTuple(args, "i:unsetopt", &option)) {
        return NULL;
    }
    if (check_curl_state(self, 1 | 2, "unsetopt") != 0) {
        return NULL;
    }

    /* early checks of option value */
    if (option <= 0)
        goto error;
    if (option >= (int)CURLOPTTYPE_OFF_T + OPTIONS_SIZE)
        goto error;
    if (option % 10000 >= OPTIONS_SIZE)
        goto error;

    return util_curl_unsetopt(self, option);

error:
    PyErr_SetString(PyExc_TypeError, "invalid arguments to unsetopt");
    return NULL;
}


static PyObject *
do_curl_setopt_string_impl(CurlObject *self, int option, PyObject *obj)
{
    char *str = NULL;
    Py_ssize_t len = -1;
    PyObject *encoded_obj;
    int res;

    /* Check that the option specified a string as well as the input */
    switch (option) {
    case CURLOPT_CAINFO:
    case CURLOPT_CAPATH:
    case CURLOPT_COOKIE:
    case CURLOPT_COOKIEFILE:
    case CURLOPT_COOKIELIST:
    case CURLOPT_COOKIEJAR:
    case CURLOPT_CUSTOMREQUEST:
    case CURLOPT_EGDSOCKET:
    /* use CURLOPT_ENCODING instead of CURLOPT_ACCEPT_ENCODING
    for compatibility with older libcurls */
    case CURLOPT_ENCODING:
    case CURLOPT_FTPPORT:
    case CURLOPT_INTERFACE:
    case CURLOPT_KEYPASSWD:
    case CURLOPT_NETRC_FILE:
    case CURLOPT_PROXY:
    case CURLOPT_PROXYUSERPWD:
#ifdef HAVE_CURLOPT_PROXYUSERNAME
    case CURLOPT_PROXYUSERNAME:
    case CURLOPT_PROXYPASSWORD:
#endif
    case CURLOPT_RANDOM_FILE:
    case CURLOPT_RANGE:
    case CURLOPT_REFERER:
    case CURLOPT_SSLCERT:
    case CURLOPT_SSLCERTTYPE:
    case CURLOPT_SSLENGINE:
    case CURLOPT_SSLKEY:
    case CURLOPT_SSLKEYTYPE:
    case CURLOPT_SSL_CIPHER_LIST:
    case CURLOPT_URL:
    case CURLOPT_USERAGENT:
    case CURLOPT_USERPWD:
#ifdef HAVE_CURLOPT_USERNAME
    case CURLOPT_USERNAME:
    case CURLOPT_PASSWORD:
#endif
    case CURLOPT_FTP_ALTERNATIVE_TO_USER:
    case CURLOPT_SSH_PUBLIC_KEYFILE:
    case CURLOPT_SSH_PRIVATE_KEYFILE:
    case CURLOPT_COPYPOSTFIELDS:
    case CURLOPT_SSH_HOST_PUBLIC_KEY_MD5:
    case CURLOPT_CRLFILE:
    case CURLOPT_ISSUERCERT:
#if LIBCURL_VERSION_NUM >= MAKE_LIBCURL_VERSION(7, 20, 0)
    case CURLOPT_RTSP_STREAM_URI:
    case CURLOPT_RTSP_SESSION_ID:
    case CURLOPT_RTSP_TRANSPORT:
#endif
#ifdef HAVE_CURLOPT_DNS_SERVERS
    case CURLOPT_DNS_SERVERS:
#endif
#ifdef HAVE_CURLOPT_NOPROXY
    case CURLOPT_NOPROXY:
#endif
#ifdef HAVE_CURL_7_19_4_OPTS
    case CURLOPT_SOCKS5_GSSAPI_SERVICE:
#endif
#ifdef HAVE_CURL_7_19_6_OPTS
    case CURLOPT_SSH_KNOWNHOSTS:
#endif
#ifdef HAVE_CURL_7_20_0_OPTS
    case CURLOPT_MAIL_FROM:
#endif
#ifdef HAVE_CURL_7_25_0_OPTS
    case CURLOPT_MAIL_AUTH:
#endif
#if LIBCURL_VERSION_NUM >= MAKE_LIBCURL_VERSION(7, 39, 0)
    case CURLOPT_PINNEDPUBLICKEY:
#endif
#if LIBCURL_VERSION_NUM >= MAKE_LIBCURL_VERSION(7, 43, 0)
    case CURLOPT_SERVICE_NAME:
    case CURLOPT_PROXY_SERVICE_NAME:
#endif
#if LIBCURL_VERSION_NUM >= MAKE_LIBCURL_VERSION(7, 21, 0)
    case CURLOPT_WILDCARDMATCH:
#endif
#if LIBCURL_VERSION_NUM >= MAKE_LIBCURL_VERSION(7, 40, 0)
    case CURLOPT_UNIX_SOCKET_PATH:
#endif
#if LIBCURL_VERSION_NUM >= MAKE_LIBCURL_VERSION(7, 21, 4)
    case CURLOPT_TLSAUTH_TYPE:
    case CURLOPT_TLSAUTH_USERNAME:
    case CURLOPT_TLSAUTH_PASSWORD:
#endif
#if LIBCURL_VERSION_NUM >= MAKE_LIBCURL_VERSION(7, 45, 0)
    case CURLOPT_DEFAULT_PROTOCOL:
#endif
#if LIBCURL_VERSION_NUM >= MAKE_LIBCURL_VERSION(7, 34, 0)
    case CURLOPT_LOGIN_OPTIONS:
#endif
#if LIBCURL_VERSION_NUM >= MAKE_LIBCURL_VERSION(7, 33, 0)
    case CURLOPT_XOAUTH2_BEARER:
#endif
#if LIBCURL_VERSION_NUM >= MAKE_LIBCURL_VERSION(7, 52, 0)
    case CURLOPT_PROXY_CAPATH:
    case CURLOPT_PROXY_CAINFO:
    case CURLOPT_PRE_PROXY:
    case CURLOPT_PROXY_SSLCERT:
    case CURLOPT_PROXY_SSLCERTTYPE:
    case CURLOPT_PROXY_SSLKEY:
    case CURLOPT_PROXY_SSLKEYTYPE:
#endif
    case CURLOPT_KRBLEVEL:
        str = PyText_AsString_NoNUL(obj, &encoded_obj);
        if (str == NULL)
            return NULL;
        break;
    case CURLOPT_POSTFIELDS:
        if (PyText_AsStringAndSize(obj, &str, &len, &encoded_obj) != 0)
            return NULL;
        /* automatically set POSTFIELDSIZE */
        if (len <= INT_MAX) {
            res = curl_easy_setopt(self->handle, CURLOPT_POSTFIELDSIZE, (long)len);
        } else {
            res = curl_easy_setopt(self->handle, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)len);
        }
        if (res != CURLE_OK) {
            PyText_EncodedDecref(encoded_obj);
            CURLERROR_RETVAL();
        }
        break;
    default:
        PyErr_SetString(PyExc_TypeError, "strings are not supported for this option");
        return NULL;
    }
    assert(str != NULL);
    /* Call setopt */
    res = curl_easy_setopt(self->handle, (CURLoption)option, str);
    /* Check for errors */
    if (res != CURLE_OK) {
        PyText_EncodedDecref(encoded_obj);
        CURLERROR_RETVAL();
    }
    /* libcurl does not copy the value of CURLOPT_POSTFIELDS */
    if (option == CURLOPT_POSTFIELDS) {
        PyObject *store_obj;

        /* if obj was bytes, it was not encoded, and we need to incref obj.
         * if obj was unicode, it was encoded, and we need to incref
         * encoded_obj - except we can simply transfer ownership.
         */
        if (encoded_obj) {
            store_obj = encoded_obj;
        } else {
            /* no encoding is performed, incref the original object. */
            store_obj = obj;
            Py_INCREF(store_obj);
        }

        util_curl_xdecref(self, PYCURL_MEMGROUP_POSTFIELDS, self->handle);
        self->postfields_obj = store_obj;
    } else {
        PyText_EncodedDecref(encoded_obj);
    }
    Py_RETURN_NONE;
}


#define IS_LONG_OPTION(o)   (o < CURLOPTTYPE_OBJECTPOINT)
#define IS_OFF_T_OPTION(o)  (o >= CURLOPTTYPE_OFF_T)


static PyObject *
do_curl_setopt_int(CurlObject *self, int option, PyObject *obj)
{
    long d;
    PY_LONG_LONG ld;
    int res;

    if (IS_LONG_OPTION(option)) {
        d = PyInt_AsLong(obj);
        res = curl_easy_setopt(self->handle, (CURLoption)option, (long)d);
    } else if (IS_OFF_T_OPTION(option)) {
        /* this path should only be taken in Python 3 */
        ld = PyLong_AsLongLong(obj);
        res = curl_easy_setopt(self->handle, (CURLoption)option, (curl_off_t)ld);
    } else {
        PyErr_SetString(PyExc_TypeError, "integers are not supported for this option");
        return NULL;
    }
    if (res != CURLE_OK) {
        CURLERROR_RETVAL();
    }
    Py_RETURN_NONE;
}


static PyObject *
do_curl_setopt_long(CurlObject *self, int option, PyObject *obj)
{
    int res;
    PY_LONG_LONG d = PyLong_AsLongLong(obj);
    if (d == -1 && PyErr_Occurred())
        return NULL;

    if (IS_LONG_OPTION(option) && (long)d == d)
        res = curl_easy_setopt(self->handle, (CURLoption)option, (long)d);
    else if (IS_OFF_T_OPTION(option) && (curl_off_t)d == d)
        res = curl_easy_setopt(self->handle, (CURLoption)option, (curl_off_t)d);
    else {
        PyErr_SetString(PyExc_TypeError, "longs are not supported for this option");
        return NULL;
    }
    if (res != CURLE_OK) {
        CURLERROR_RETVAL();
    }
    Py_RETURN_NONE;
}


#undef IS_LONG_OPTION
#undef IS_OFF_T_OPTION


#if PY_MAJOR_VERSION < 3 && !defined(PYCURL_AVOID_STDIO)
static PyObject *
do_curl_setopt_file_passthrough(CurlObject *self, int option, PyObject *obj)
{
    FILE *fp;
    int res;

    fp = PyFile_AsFile(obj);
    if (fp == NULL) {
        PyErr_SetString(PyExc_TypeError, "second argument must be open file");
        return NULL;
    }
    
    switch (option) {
    case CURLOPT_READDATA:
        res = curl_easy_setopt(self->handle, CURLOPT_READFUNCTION, fread);
        if (res != CURLE_OK) {
            CURLERROR_RETVAL();
        }
        break;
    case CURLOPT_WRITEDATA:
        res = curl_easy_setopt(self->handle, CURLOPT_WRITEFUNCTION, fwrite);
        if (res != CURLE_OK) {
            CURLERROR_RETVAL();
        }
        break;
    case CURLOPT_WRITEHEADER:
        res = curl_easy_setopt(self->handle, CURLOPT_HEADERFUNCTION, fwrite);
        if (res != CURLE_OK) {
            CURLERROR_RETVAL();
        }
        break;
    default:
        PyErr_SetString(PyExc_TypeError, "files are not supported for this option");
        return NULL;
    }

    res = curl_easy_setopt(self->handle, (CURLoption)option, fp);
    if (res != CURLE_OK) {
        /*
        If we get here fread/fwrite are set as callbacks but the file pointer
        is not set, program will crash if it does not reset read/write
        callback. Also, we won't do the memory management later in this
        function.
        */
        CURLERROR_RETVAL();
    }
    Py_INCREF(obj);

    switch (option) {
    case CURLOPT_READDATA:
        Py_CLEAR(self->readdata_fp);
        self->readdata_fp = obj;
        break;
    case CURLOPT_WRITEDATA:
        Py_CLEAR(self->writedata_fp);
        self->writedata_fp = obj;
        break;
    case CURLOPT_WRITEHEADER:
        Py_CLEAR(self->writeheader_fp);
        self->writeheader_fp = obj;
        break;
    default:
        assert(0);
        break;
    }
    /* Return success */
    Py_RETURN_NONE;
}
#endif


static PyObject *
do_curl_setopt_httppost(CurlObject *self, int option, int which, PyObject *obj)
{
    struct curl_httppost *post = NULL;
    struct curl_httppost *last = NULL;
    /* List of all references that have been INCed as a result of
     * this operation */
    PyObject *ref_params = NULL;
    PyObject *nencoded_obj, *cencoded_obj, *oencoded_obj;
    int which_httppost_item, which_httppost_option;
    PyObject *httppost_option;
    Py_ssize_t i, len;
    int res;

    len = PyListOrTuple_Size(obj, which);
    if (len == 0)
        Py_RETURN_NONE;

    for (i = 0; i < len; i++) {
        char *nstr = NULL, *cstr = NULL;
        Py_ssize_t nlen = -1, clen = -1;
        PyObject *listitem = PyListOrTuple_GetItem(obj, i, which);

        which_httppost_item = PyListOrTuple_Check(listitem);
        if (!which_httppost_item) {
            PyErr_SetString(PyExc_TypeError, "list items must be list or tuple objects");
            goto error;
        }
        if (PyListOrTuple_Size(listitem, which_httppost_item) != 2) {
            PyErr_SetString(PyExc_TypeError, "list or tuple must contain two elements (name, value)");
            goto error;
        }
        if (PyText_AsStringAndSize(PyListOrTuple_GetItem(listitem, 0, which_httppost_item),
                &nstr, &nlen, &nencoded_obj) != 0) {
            PyErr_SetString(PyExc_TypeError, "list or tuple must contain a byte string or Unicode string with ASCII code points only as first element");
            goto error;
        }
        httppost_option = PyListOrTuple_GetItem(listitem, 1, which_httppost_item);
        if (PyText_Check(httppost_option)) {
            /* Handle strings as second argument for backwards compatibility */

            if (PyText_AsStringAndSize(httppost_option, &cstr, &clen, &cencoded_obj)) {
                PyText_EncodedDecref(nencoded_obj);
                create_and_set_error_object(self, CURLE_BAD_FUNCTION_ARGUMENT);
                goto error;
            }
            /* INFO: curl_formadd() internally does memdup() the data, so
             * embedded NUL characters _are_ allowed here. */
            res = curl_formadd(&post, &last,
                               CURLFORM_COPYNAME, nstr,
                               CURLFORM_NAMELENGTH, (long) nlen,
                               CURLFORM_COPYCONTENTS, cstr,
                               CURLFORM_CONTENTSLENGTH, (long) clen,
                               CURLFORM_END);
            PyText_EncodedDecref(cencoded_obj);
            if (res != CURLE_OK) {
                PyText_EncodedDecref(nencoded_obj);
                CURLERROR_SET_RETVAL();
                goto error;
            }
        }
        /* assignment is intended */
        else if ((which_httppost_option = PyListOrTuple_Check(httppost_option))) {
            /* Supports content, file and content-type */
            Py_ssize_t tlen = PyListOrTuple_Size(httppost_option, which_httppost_option);
            int j, k, l;
            struct curl_forms *forms = NULL;

            /* Sanity check that there are at least two tuple items */
            if (tlen < 2) {
                PyText_EncodedDecref(nencoded_obj);
                PyErr_SetString(PyExc_TypeError, "list or tuple must contain at least one option and one value");
                goto error;
            }

            if (tlen % 2 == 1) {
                PyText_EncodedDecref(nencoded_obj);
                PyErr_SetString(PyExc_TypeError, "list or tuple must contain an even number of items");
                goto error;
            }

            /* Allocate enough space to accommodate length options for content or buffers, plus a terminator. */
            forms = PyMem_New(struct curl_forms, (tlen*2) + 1);
            if (forms == NULL) {
                PyText_EncodedDecref(nencoded_obj);
                PyErr_NoMemory();
                goto error;
            }

            /* Iterate all the tuple members pairwise */
            for (j = 0, k = 0, l = 0; j < tlen; j += 2, l++) {
                char *ostr;
                Py_ssize_t olen;
                int val;

                if (j == (tlen-1)) {
                    PyErr_SetString(PyExc_TypeError, "expected value");
                    PyMem_Free(forms);
                    PyText_EncodedDecref(nencoded_obj);
                    goto error;
                }
                if (!PyInt_Check(PyListOrTuple_GetItem(httppost_option, j, which_httppost_option))) {
                    PyErr_SetString(PyExc_TypeError, "option must be an integer");
                    PyMem_Free(forms);
                    PyText_EncodedDecref(nencoded_obj);
                    goto error;
                }
                if (!PyText_Check(PyListOrTuple_GetItem(httppost_option, j+1, which_httppost_option))) {
                    PyErr_SetString(PyExc_TypeError, "value must be a byte string or a Unicode string with ASCII code points only");
                    PyMem_Free(forms);
                    PyText_EncodedDecref(nencoded_obj);
                    goto error;
                }

                val = PyLong_AsLong(PyListOrTuple_GetItem(httppost_option, j, which_httppost_option));
                if (val != CURLFORM_COPYCONTENTS &&
                    val != CURLFORM_FILE &&
                    val != CURLFORM_FILENAME &&
                    val != CURLFORM_CONTENTTYPE &&
                    val != CURLFORM_BUFFER &&
                    val != CURLFORM_BUFFERPTR)
                {
                    PyErr_SetString(PyExc_TypeError, "unsupported option");
                    PyMem_Free(forms);
                    PyText_EncodedDecref(nencoded_obj);
                    goto error;
                }

                if (PyText_AsStringAndSize(PyListOrTuple_GetItem(httppost_option, j+1, which_httppost_option), &ostr, &olen, &oencoded_obj)) {
                    /* exception should be already set */
                    PyMem_Free(forms);
                    PyText_EncodedDecref(nencoded_obj);
                    goto error;
                }
                forms[k].option = val;
                forms[k].value = ostr;
                ++k;

                if (val == CURLFORM_COPYCONTENTS) {
                    /* Contents can contain \0 bytes so we specify the length */
                    forms[k].option = CURLFORM_CONTENTSLENGTH;
                    forms[k].value = (const char *)olen;
                    ++k;
                } else if (val == CURLFORM_BUFFERPTR) {
                    PyObject *obj = NULL;

                    if (ref_params == NULL) {
                        ref_params = PyList_New((Py_ssize_t)0);
                        if (ref_params == NULL) {
                            PyText_EncodedDecref(oencoded_obj);
                            PyMem_Free(forms);
                            PyText_EncodedDecref(nencoded_obj);
                            goto error;
                        }
                    }

                    /* Keep a reference to the object that holds the ostr buffer. */
                    if (oencoded_obj == NULL) {
                        obj = PyListOrTuple_GetItem(httppost_option, j+1, which_httppost_option);
                    }
                    else {
                        obj = oencoded_obj;
                    }

                    /* Ensure that the buffer remains alive until curl_easy_cleanup() */
                    if (PyList_Append(ref_params, obj) != 0) {
                        PyText_EncodedDecref(oencoded_obj);
                        PyMem_Free(forms);
                        PyText_EncodedDecref(nencoded_obj);
                        goto error;
                    }

                    /* As with CURLFORM_COPYCONTENTS, specify the length. */
                    forms[k].option = CURLFORM_BUFFERLENGTH;
                    forms[k].value = (const char *)olen;
                    ++k;
                }
            }
            forms[k].option = CURLFORM_END;
            res = curl_formadd(&post, &last,
                               CURLFORM_COPYNAME, nstr,
                               CURLFORM_NAMELENGTH, (long) nlen,
                               CURLFORM_ARRAY, forms,
                               CURLFORM_END);
            PyText_EncodedDecref(oencoded_obj);
            PyMem_Free(forms);
            if (res != CURLE_OK) {
                PyText_EncodedDecref(nencoded_obj);
                CURLERROR_SET_RETVAL();
                goto error;
            }
        } else {
            /* Some other type was given, ignore */
            PyText_EncodedDecref(nencoded_obj);
            PyErr_SetString(PyExc_TypeError, "unsupported second type in tuple");
            goto error;
        }
        PyText_EncodedDecref(nencoded_obj);
    }
    res = curl_easy_setopt(self->handle, CURLOPT_HTTPPOST, post);
    /* Check for errors */
    if (res != CURLE_OK) {
        CURLERROR_SET_RETVAL();
        goto error;
    }
    /* Finally, free previously allocated httppost, ZAP any
     * buffer references, and update */
    curl_formfree(self->httppost);
    util_curl_xdecref(self, PYCURL_MEMGROUP_HTTPPOST, self->handle);
    self->httppost = post;

    /* The previous list of INCed references was ZAPed above; save
     * the new one so that we can clean it up on the next
     * self->httppost free. */
    self->httppost_ref_list = ref_params;

    Py_RETURN_NONE;

error:
    curl_formfree(post);
    Py_XDECREF(ref_params);
    return NULL;
}


static PyObject *
do_curl_setopt_list(CurlObject *self, int option, int which, PyObject *obj)
{
    struct curl_slist **old_slist = NULL;
    struct curl_slist *slist = NULL;
    Py_ssize_t len;
    int res;

    switch (option) {
    case CURLOPT_HTTP200ALIASES:
        old_slist = &self->http200aliases;
        break;
    case CURLOPT_HTTPHEADER:
        old_slist = &self->httpheader;
        break;
#if LIBCURL_VERSION_NUM >= MAKE_LIBCURL_VERSION(7, 37, 0)
    case CURLOPT_PROXYHEADER:
        old_slist = &self->proxyheader;
        break;
#endif
    case CURLOPT_POSTQUOTE:
        old_slist = &self->postquote;
        break;
    case CURLOPT_PREQUOTE:
        old_slist = &self->prequote;
        break;
    case CURLOPT_QUOTE:
        old_slist = &self->quote;
        break;
    case CURLOPT_TELNETOPTIONS:
        old_slist = &self->telnetoptions;
        break;
#ifdef HAVE_CURLOPT_RESOLVE
    case CURLOPT_RESOLVE:
        old_slist = &self->resolve;
        break;
#endif
#ifdef HAVE_CURL_7_20_0_OPTS
    case CURLOPT_MAIL_RCPT:
        old_slist = &self->mail_rcpt;
        break;
#endif
#ifdef HAVE_CURLOPT_CONNECT_TO
    case CURLOPT_CONNECT_TO:
        old_slist = &self->connect_to;
        break;
#endif
    default:
        /* None of the list options were recognized, raise exception */
        PyErr_SetString(PyExc_TypeError, "lists are not supported for this option");
        return NULL;
    }

    len = PyListOrTuple_Size(obj, which);
    if (len == 0)
        Py_RETURN_NONE;

    /* Just to be sure we do not bug off here */
    assert(old_slist != NULL && slist == NULL);

    /* Handle regular list operations on the other options */
    slist = pycurl_list_or_tuple_to_slist(which, obj, len);
    if (slist == NULL) {
        return NULL;
    }
    res = curl_easy_setopt(self->handle, (CURLoption)option, slist);
    /* Check for errors */
    if (res != CURLE_OK) {
        curl_slist_free_all(slist);
        CURLERROR_RETVAL();
    }
    /* Finally, free previously allocated list and update */
    curl_slist_free_all(*old_slist);
    *old_slist = slist;

    Py_RETURN_NONE;
}


static PyObject *
do_curl_setopt_callable(CurlObject *self, int option, PyObject *obj)
{
    /* We use function types here to make sure that our callback
     * definitions exactly match the <curl/curl.h> interface.
     */
    const curl_write_callback w_cb = write_callback;
    const curl_write_callback h_cb = header_callback;
    const curl_read_callback r_cb = read_callback;
    const curl_progress_callback pro_cb = progress_callback;
#if LIBCURL_VERSION_NUM >= MAKE_LIBCURL_VERSION(7, 32, 0)
    const curl_xferinfo_callback xferinfo_cb = xferinfo_callback;
#endif
    const curl_debug_callback debug_cb = debug_callback;
    const curl_ioctl_callback ioctl_cb = ioctl_callback;
    const curl_opensocket_callback opensocket_cb = opensocket_callback;
#if LIBCURL_VERSION_NUM >= MAKE_LIBCURL_VERSION(7, 21, 7)
    const curl_closesocket_callback closesocket_cb = closesocket_callback;
#endif
    const curl_seek_callback seek_cb = seek_callback;

    switch(option) {
    case CURLOPT_WRITEFUNCTION:
        Py_INCREF(obj);
        Py_CLEAR(self->writedata_fp);
        Py_CLEAR(self->w_cb);
        self->w_cb = obj;
        curl_easy_setopt(self->handle, CURLOPT_WRITEFUNCTION, w_cb);
        curl_easy_setopt(self->handle, CURLOPT_WRITEDATA, self);
        break;
    case CURLOPT_HEADERFUNCTION:
        Py_INCREF(obj);
        Py_CLEAR(self->writeheader_fp);
        Py_CLEAR(self->h_cb);
        self->h_cb = obj;
        curl_easy_setopt(self->handle, CURLOPT_HEADERFUNCTION, h_cb);
        curl_easy_setopt(self->handle, CURLOPT_WRITEHEADER, self);
        break;
    case CURLOPT_READFUNCTION:
        Py_INCREF(obj);
        Py_CLEAR(self->readdata_fp);
        Py_CLEAR(self->r_cb);
        self->r_cb = obj;
        curl_easy_setopt(self->handle, CURLOPT_READFUNCTION, r_cb);
        curl_easy_setopt(self->handle, CURLOPT_READDATA, self);
        break;
    case CURLOPT_PROGRESSFUNCTION:
        Py_INCREF(obj);
        Py_CLEAR(self->pro_cb);
        self->pro_cb = obj;
        curl_easy_setopt(self->handle, CURLOPT_PROGRESSFUNCTION, pro_cb);
        curl_easy_setopt(self->handle, CURLOPT_PROGRESSDATA, self);
        break;
#if LIBCURL_VERSION_NUM >= MAKE_LIBCURL_VERSION(7, 32, 0)
    case CURLOPT_XFERINFOFUNCTION:
        Py_INCREF(obj);
        Py_CLEAR(self->xferinfo_cb);
        self->xferinfo_cb = obj;
        curl_easy_setopt(self->handle, CURLOPT_XFERINFOFUNCTION, xferinfo_cb);
        curl_easy_setopt(self->handle, CURLOPT_XFERINFODATA, self);
        break;
#endif
    case CURLOPT_DEBUGFUNCTION:
        Py_INCREF(obj);
        Py_CLEAR(self->debug_cb);
        self->debug_cb = obj;
        curl_easy_setopt(self->handle, CURLOPT_DEBUGFUNCTION, debug_cb);
        curl_easy_setopt(self->handle, CURLOPT_DEBUGDATA, self);
        break;
    case CURLOPT_IOCTLFUNCTION:
        Py_INCREF(obj);
        Py_CLEAR(self->ioctl_cb);
        self->ioctl_cb = obj;
        curl_easy_setopt(self->handle, CURLOPT_IOCTLFUNCTION, ioctl_cb);
        curl_easy_setopt(self->handle, CURLOPT_IOCTLDATA, self);
        break;
    case CURLOPT_OPENSOCKETFUNCTION:
        Py_INCREF(obj);
        Py_CLEAR(self->opensocket_cb);
        self->opensocket_cb = obj;
        curl_easy_setopt(self->handle, CURLOPT_OPENSOCKETFUNCTION, opensocket_cb);
        curl_easy_setopt(self->handle, CURLOPT_OPENSOCKETDATA, self);
        break;
#if LIBCURL_VERSION_NUM >= MAKE_LIBCURL_VERSION(7, 21, 7)
    case CURLOPT_CLOSESOCKETFUNCTION:
        Py_INCREF(obj);
        Py_CLEAR(self->closesocket_cb);
        self->closesocket_cb = obj;
        curl_easy_setopt(self->handle, CURLOPT_CLOSESOCKETFUNCTION, closesocket_cb);
        curl_easy_setopt(self->handle, CURLOPT_CLOSESOCKETDATA, self);
        break;
#endif
    case CURLOPT_SOCKOPTFUNCTION:
        Py_INCREF(obj);
        Py_CLEAR(self->sockopt_cb);
        self->sockopt_cb = obj;
        curl_easy_setopt(self->handle, CURLOPT_SOCKOPTFUNCTION, sockopt_cb);
        curl_easy_setopt(self->handle, CURLOPT_SOCKOPTDATA, self);
        break;
#ifdef HAVE_CURL_7_19_6_OPTS
    case CURLOPT_SSH_KEYFUNCTION:
        Py_INCREF(obj);
        Py_CLEAR(self->ssh_key_cb);
        self->ssh_key_cb = obj;
        curl_easy_setopt(self->handle, CURLOPT_SSH_KEYFUNCTION, ssh_key_cb);
        curl_easy_setopt(self->handle, CURLOPT_SSH_KEYDATA, self);
        break;
#endif
    case CURLOPT_SEEKFUNCTION:
        Py_INCREF(obj);
        Py_CLEAR(self->seek_cb);
        self->seek_cb = obj;
        curl_easy_setopt(self->handle, CURLOPT_SEEKFUNCTION, seek_cb);
        curl_easy_setopt(self->handle, CURLOPT_SEEKDATA, self);
        break;

    default:
        /* None of the function options were recognized, raise exception */
        PyErr_SetString(PyExc_TypeError, "functions are not supported for this option");
        return NULL;
    }
    Py_RETURN_NONE;
}


static PyObject *
do_curl_setopt_share(CurlObject *self, PyObject *obj)
{
    CurlShareObject *share;
    int res;

    if (self->share == NULL && (obj == NULL || obj == Py_None))
        Py_RETURN_NONE;

    if (self->share) {
        if (obj != Py_None) {
            PyErr_SetString(ErrorObject, "Curl object already sharing. Unshare first.");
            return NULL;
        }
        else {
            share = self->share;
            res = curl_easy_setopt(self->handle, CURLOPT_SHARE, NULL);
            if (res != CURLE_OK) {
                CURLERROR_RETVAL();
            }
            self->share = NULL;
            Py_DECREF(share);
            Py_RETURN_NONE;
        }
    }
    if (Py_TYPE(obj) != p_CurlShare_Type) {
        PyErr_SetString(PyExc_TypeError, "invalid arguments to setopt");
        return NULL;
    }
    share = (CurlShareObject*)obj;
    res = curl_easy_setopt(self->handle, CURLOPT_SHARE, share->share_handle);
    if (res != CURLE_OK) {
        CURLERROR_RETVAL();
    }
    self->share = share;
    Py_INCREF(share);
    Py_RETURN_NONE;
}


PYCURL_INTERNAL PyObject *
do_curl_setopt_filelike(CurlObject *self, int option, PyObject *obj)
{
    const char *method_name;
    PyObject *method;

    if (option == CURLOPT_READDATA) {
        method_name = "read";
    } else {
        method_name = "write";
    }
    method = PyObject_GetAttrString(obj, method_name);
    if (method) {
        PyObject *arglist;
        PyObject *rv;

        switch (option) {
            case CURLOPT_READDATA:
                option = CURLOPT_READFUNCTION;
                break;
            case CURLOPT_WRITEDATA:
                option = CURLOPT_WRITEFUNCTION;
                break;
            case CURLOPT_WRITEHEADER:
                option = CURLOPT_HEADERFUNCTION;
                break;
            default:
                PyErr_SetString(PyExc_TypeError, "objects are not supported for this option");
                Py_DECREF(method);
                return NULL;
        }

        arglist = Py_BuildValue("(iO)", option, method);
        /* reference is now in arglist */
        Py_DECREF(method);
        if (arglist == NULL) {
            return NULL;
        }
        rv = do_curl_setopt(self, arglist);
        Py_DECREF(arglist);
        return rv;
    } else {
        if (option == CURLOPT_READDATA) {
            PyErr_SetString(PyExc_TypeError, "object given without a read method");
        } else {
            PyErr_SetString(PyExc_TypeError, "object given without a write method");
        }
        return NULL;
    }
}


PYCURL_INTERNAL PyObject *
do_curl_setopt(CurlObject *self, PyObject *args)
{
    int option;
    PyObject *obj;
    int which;

    if (!PyArg_ParseTuple(args, "iO:setopt", &option, &obj))
        return NULL;
    if (check_curl_state(self, 1 | 2, "setopt") != 0)
        return NULL;

    /* early checks of option value */
    if (option <= 0)
        goto error;
    if (option >= (int)CURLOPTTYPE_OFF_T + OPTIONS_SIZE)
        goto error;
    if (option % 10000 >= OPTIONS_SIZE)
        goto error;

    /* Handle the case of None as the call of unsetopt() */
    if (obj == Py_None) {
        return util_curl_unsetopt(self, option);
    }

    /* Handle the case of string arguments */
    if (PyText_Check(obj)) {
        return do_curl_setopt_string_impl(self, option, obj);
    }

    /* Handle the case of integer arguments */
    if (PyInt_Check(obj)) {
        return do_curl_setopt_int(self, option, obj);
    }

    /* Handle the case of long arguments (used by *_LARGE options) */
    if (PyLong_Check(obj)) {
        return do_curl_setopt_long(self, option, obj);
    }

#if PY_MAJOR_VERSION < 3 && !defined(PYCURL_AVOID_STDIO)
    /* Handle the case of file objects */
    if (PyFile_Check(obj)) {
        return do_curl_setopt_file_passthrough(self, option, obj);
    }
#endif

    /* Handle the case of list or tuple objects */
    which = PyListOrTuple_Check(obj);
    if (which) {
        if (option == CURLOPT_HTTPPOST) {
            return do_curl_setopt_httppost(self, option, which, obj);
        } else {
            return do_curl_setopt_list(self, option, which, obj);
        }
    }

    /* Handle the case of function objects for callbacks */
    if (PyFunction_Check(obj) || PyCFunction_Check(obj) ||
        PyCallable_Check(obj) || PyMethod_Check(obj)) {
        return do_curl_setopt_callable(self, option, obj);
    }
    /* handle the SHARE case */
    if (option == CURLOPT_SHARE) {
        return do_curl_setopt_share(self, obj);
    }

    /*
    Handle the case of file-like objects.

    Given an object with a write method, we will call the write method
    from the appropriate callback.

    Files in Python 3 are no longer FILE * instances and therefore cannot
    be directly given to curl, therefore this method handles all I/O to
    Python objects.
    
    In Python 2 true file objects are FILE * instances and will be handled
    by stdio passthrough code invoked above, and file-like objects will
    be handled by this method.
    */
    if (option == CURLOPT_READDATA ||
        option == CURLOPT_WRITEDATA ||
        option == CURLOPT_WRITEHEADER)
    {
        return do_curl_setopt_filelike(self, option, obj);
    }

    /* Failed to match any of the function signatures -- return error */
error:
    PyErr_SetString(PyExc_TypeError, "invalid arguments to setopt");
    return NULL;
}


PYCURL_INTERNAL PyObject *
do_curl_setopt_string(CurlObject *self, PyObject *args)
{
    int option;
    PyObject *obj;

    if (!PyArg_ParseTuple(args, "iO:setopt", &option, &obj))
        return NULL;
    if (check_curl_state(self, 1 | 2, "setopt") != 0)
        return NULL;

    /* Handle the case of string arguments */
    if (PyText_Check(obj)) {
        return do_curl_setopt_string_impl(self, option, obj);
    }

    /* Failed to match any of the function signatures -- return error */
    PyErr_SetString(PyExc_TypeError, "invalid arguments to setopt_string");
    return NULL;
}


#if defined(HAVE_CURL_OPENSSL)
/* load ca certs from string */
PYCURL_INTERNAL PyObject *
do_curl_set_ca_certs(CurlObject *self, PyObject *args)
{
    PyObject *cadata;
    PyObject *encoded_obj;
    char *buffer;
    Py_ssize_t length;
    int res;

    if (!PyArg_ParseTuple(args, "O:cadata", &cadata))
        return NULL;

    // This may result in cadata string being encoded twice,
    // not going to worry about it for now
    if (!PyText_Check(cadata)) {
        PyErr_SetString(PyExc_TypeError, "set_ca_certs argument must be a byte string or a Unicode string with ASCII code points only");
        return NULL;
    }

    res = PyText_AsStringAndSize(cadata, &buffer, &length, &encoded_obj);
    if (res) {
        PyErr_SetString(PyExc_TypeError, "set_ca_certs argument must be a byte string or a Unicode string with ASCII code points only");
        return NULL;
    }

    Py_CLEAR(self->ca_certs_obj);
    if (encoded_obj) {
        self->ca_certs_obj = encoded_obj;
    } else {
        Py_INCREF(cadata);
        self->ca_certs_obj = cadata;
    }

    res = curl_easy_setopt(self->handle, CURLOPT_SSL_CTX_FUNCTION, (curl_ssl_ctx_callback) ssl_ctx_callback);
    if (res != CURLE_OK) {
        Py_CLEAR(self->ca_certs_obj);
        CURLERROR_RETVAL();
    }

    res = curl_easy_setopt(self->handle, CURLOPT_SSL_CTX_DATA, self);
    if (res != CURLE_OK) {
        Py_CLEAR(self->ca_certs_obj);
        CURLERROR_RETVAL();
    }

    Py_RETURN_NONE;
}
#endif



/* --------------- perform --------------- */

PYCURL_INTERNAL PyObject *
do_curl_perform(CurlObject *self)
{
    int res;

    if (check_curl_state(self, 1 | 2, "perform") != 0) {
        return NULL;
    }

    PYCURL_BEGIN_ALLOW_THREADS
    res = curl_easy_perform(self->handle);
    PYCURL_END_ALLOW_THREADS

    if (res != CURLE_OK) {
        CURLERROR_RETVAL();
    }
    Py_RETURN_NONE;
}


PYCURL_INTERNAL PyObject *
do_curl_perform_rb(CurlObject *self)
{
    PyObject *v, *io;
    
    io = PyEval_CallObject(bytesio, NULL);
    if (io == NULL) {
        return NULL;
    }
    
    v = do_curl_setopt_filelike(self, CURLOPT_WRITEDATA, io);
    if (v == NULL) {
        Py_DECREF(io);
        return NULL;
    }
    
    v = do_curl_perform(self);
    if (v == NULL) {
        return NULL;
    }
    
    v = PyObject_CallMethod(io, "getvalue", NULL);
    Py_DECREF(io);
    return v;
}

#if PY_MAJOR_VERSION >= 3
PYCURL_INTERNAL PyObject *
do_curl_perform_rs(CurlObject *self)
{
    PyObject *v, *decoded;
    
    v = do_curl_perform_rb(self);
    if (v == NULL) {
        return NULL;
    }
    
    decoded = PyUnicode_FromEncodedObject(v, NULL, NULL);
    Py_DECREF(v);
    return decoded;
}
#endif


/* --------------- pause --------------- */


/* curl_easy_pause() can be called from inside a callback or outside */
PYCURL_INTERNAL PyObject *
do_curl_pause(CurlObject *self, PyObject *args)
{
    int bitmask;
    CURLcode res;
#ifdef WITH_THREAD
    PyThreadState *saved_state;
#endif

    if (!PyArg_ParseTuple(args, "i:pause", &bitmask)) {
        return NULL;
    }
    if (check_curl_state(self, 1, "pause") != 0) {
        return NULL;
    }

#ifdef WITH_THREAD
    /* Save handle to current thread (used as context for python callbacks) */
    saved_state = self->state;
    PYCURL_BEGIN_ALLOW_THREADS

    /* We must allow threads here because unpausing a handle can cause
       some of its callbacks to be invoked immediately, from inside
       curl_easy_pause() */
#endif

    res = curl_easy_pause(self->handle, bitmask);

#ifdef WITH_THREAD
    PYCURL_END_ALLOW_THREADS

    /* Restore the thread-state to whatever it was on entry */
    self->state = saved_state;
#endif

    if (res != CURLE_OK) {
        CURLERROR_MSG("pause/unpause failed");
    } else {
        Py_INCREF(Py_None);
        return Py_None;
    }
}



#if defined(WIN32)
# define PYCURL_STRINGIZE_IMP(x) #x
# define PYCURL_STRINGIZE(x) PYCURL_STRINGIZE_IMP(x)
# define PYCURL_VERSION_STRING PYCURL_STRINGIZE(PYCURL_VERSION)
#else
# define PYCURL_VERSION_STRING PYCURL_VERSION
#endif

#define PYCURL_VERSION_PREFIX "PycURL/" PYCURL_VERSION_STRING

PYCURL_INTERNAL char *empty_keywords[] = { NULL };

PYCURL_INTERNAL PyObject *bytesio = NULL;
PYCURL_INTERNAL PyObject *stringio = NULL;

/* Initialized during module init */
PYCURL_INTERNAL char *g_pycurl_useragent = NULL;

/* Type objects */
PYCURL_INTERNAL PyObject *ErrorObject = NULL;
PYCURL_INTERNAL PyTypeObject *p_Curl_Type = NULL;
PYCURL_INTERNAL PyTypeObject *p_CurlMulti_Type = NULL;
PYCURL_INTERNAL PyTypeObject *p_CurlShare_Type = NULL;
#ifdef HAVE_CURL_7_19_6_OPTS
PYCURL_INTERNAL PyObject *khkey_type = NULL;
#endif
PYCURL_INTERNAL PyObject *curl_sockaddr_type = NULL;

PYCURL_INTERNAL PyObject *curlobject_constants = NULL;
PYCURL_INTERNAL PyObject *curlmultiobject_constants = NULL;
PYCURL_INTERNAL PyObject *curlshareobject_constants = NULL;


/* List of functions defined in this module */
static PyMethodDef curl_methods[] = {
    {"global_init", (PyCFunction)do_global_init, METH_VARARGS, pycurl_global_init_doc},
    {"global_cleanup", (PyCFunction)do_global_cleanup, METH_NOARGS, pycurl_global_cleanup_doc},
    {"version_info", (PyCFunction)do_version_info, METH_VARARGS, pycurl_version_info_doc},
    {NULL, NULL, 0, NULL}
};


/*************************************************************************
// module level
// Note that the object constructors (do_curl_new, do_multi_new)
// are module-level functions as well.
**************************************************************************/

static int
are_global_init_flags_valid(int flags)
{
#ifdef CURL_GLOBAL_ACK_EINTR
    /* CURL_GLOBAL_ACK_EINTR was introduced in libcurl-7.30.0 */
    return !(flags & ~(CURL_GLOBAL_ALL | CURL_GLOBAL_ACK_EINTR));
#else
    return !(flags & ~(CURL_GLOBAL_ALL));
#endif
}

PYCURL_INTERNAL PyObject *
do_global_init(PyObject *dummy, PyObject *args)
{
    int res, option;

    UNUSED(dummy);
    if (!PyArg_ParseTuple(args, "i:global_init", &option)) {
        return NULL;
    }

    if (!are_global_init_flags_valid(option)) {
        PyErr_SetString(PyExc_ValueError, "invalid option to global_init");
        return NULL;
    }

    res = curl_global_init(option);
    if (res != CURLE_OK) {
        PyErr_SetString(ErrorObject, "unable to set global option");
        return NULL;
    }

    Py_RETURN_NONE;
}


PYCURL_INTERNAL PyObject *
do_global_cleanup(PyObject *dummy)
{
    UNUSED(dummy);
    curl_global_cleanup();
#ifdef PYCURL_NEED_SSL_TSL
    pycurl_ssl_cleanup();
#endif
    Py_RETURN_NONE;
}


static PyObject *vi_str(const char *s)
{
    if (s == NULL)
        Py_RETURN_NONE;
    while (*s == ' ' || *s == '\t')
        s++;
    return PyText_FromString(s);
}

PYCURL_INTERNAL PyObject *
do_version_info(PyObject *dummy, PyObject *args)
{
    const curl_version_info_data *vi;
    PyObject *ret = NULL;
    PyObject *protocols = NULL;
    PyObject *tmp;
    Py_ssize_t i;
    int stamp = CURLVERSION_NOW;

    UNUSED(dummy);
    if (!PyArg_ParseTuple(args, "|i:version_info", &stamp)) {
        return NULL;
    }
    vi = curl_version_info((CURLversion) stamp);
    if (vi == NULL) {
        PyErr_SetString(ErrorObject, "unable to get version info");
        return NULL;
    }

    /* INFO: actually libcurl in lib/version.c does ignore
     * the "stamp" parameter, and so do we. */

    for (i = 0; vi->protocols[i] != NULL; )
        i++;
    protocols = PyTuple_New(i);
    if (protocols == NULL)
        goto error;
    for (i = 0; vi->protocols[i] != NULL; i++) {
        tmp = vi_str(vi->protocols[i]);
        if (tmp == NULL)
            goto error;
        PyTuple_SET_ITEM(protocols, i, tmp);
    }
    ret = PyTuple_New((Py_ssize_t)12);
    if (ret == NULL)
        goto error;

#define SET(i, v) \
        tmp = (v); if (tmp == NULL) goto error; PyTuple_SET_ITEM(ret, i, tmp)
    SET(0, PyInt_FromLong((long) vi->age));
    SET(1, vi_str(vi->version));
    SET(2, PyInt_FromLong(vi->version_num));
    SET(3, vi_str(vi->host));
    SET(4, PyInt_FromLong(vi->features));
    SET(5, vi_str(vi->ssl_version));
    SET(6, PyInt_FromLong(vi->ssl_version_num));
    SET(7, vi_str(vi->libz_version));
    SET(8, protocols);
    SET(9, vi_str(vi->ares));
    SET(10, PyInt_FromLong(vi->ares_num));
    SET(11, vi_str(vi->libidn));
#undef SET
    return ret;

error:
    Py_XDECREF(ret);
    Py_XDECREF(protocols);
    return NULL;
}


/* Helper functions for inserting constants into the module namespace */

static int
insobj2(PyObject *dict1, PyObject *dict2, char *name, PyObject *value)
{
    /* Insert an object into one or two dicts. Eats a reference to value.
     * See also the implementation of PyDict_SetItemString(). */
    PyObject *key = NULL;

    if (dict1 == NULL && dict2 == NULL)
        goto error;
    if (value == NULL)
        goto error;

    key = PyText_FromString(name);

    if (key == NULL)
        goto error;
#if 0
    PyString_InternInPlace(&key);   /* XXX Should we really? */
#endif
    if (dict1 != NULL) {
#if !defined(NDEBUG)
        if (PyDict_GetItem(dict1, key) != NULL) {
            fprintf(stderr, "Symbol already defined: %s\n", name);
            assert(0);
        }
#endif
        if (PyDict_SetItem(dict1, key, value) != 0)
            goto error;
    }
    if (dict2 != NULL && dict2 != dict1) {
        assert(PyDict_GetItem(dict2, key) == NULL);
        if (PyDict_SetItem(dict2, key, value) != 0)
            goto error;
    }
    Py_DECREF(key);
    Py_DECREF(value);
    return 0;

error:
    Py_XDECREF(key);
    return -1;
}

#define insobj2_modinit(dict1, dict2, name, value) \
    if (insobj2(dict1, dict2, name, value) < 0) \
        goto error


static int
insstr(PyObject *d, char *name, char *value)
{
    PyObject *v;
    int rv;

    v = PyText_FromString(value);
    if (v == NULL)
        return -1;

    rv = insobj2(d, NULL, name, v);
    if (rv < 0) {
        Py_DECREF(v);
    }
    return rv;
}

#define insstr_modinit(d, name, value) \
    do { \
        if (insstr(d, name, value) < 0) \
            goto error; \
    } while(0)

static int
insint_worker(PyObject *d, PyObject *extra, char *name, long value)
{
    PyObject *v = PyInt_FromLong(value);
    if (v == NULL)
        return -1;
    if (insobj2(d, extra, name, v) < 0) {
        Py_DECREF(v);
        return -1;
    }
    return 0;
}

#define insint(d, name, value) \
    do { \
        if (insint_worker(d, NULL, name, value) < 0) \
            goto error; \
    } while(0)

#define insint_c(d, name, value) \
    do { \
        if (insint_worker(d, curlobject_constants, name, value) < 0) \
            goto error; \
    } while(0)

#define insint_m(d, name, value) \
    do { \
        if (insint_worker(d, curlmultiobject_constants, name, value) < 0) \
            goto error; \
    } while(0)

#define insint_s(d, name, value) \
    do { \
        if (insint_worker(d, curlshareobject_constants, name, value) < 0) \
            goto error; \
    } while(0)


#if PY_MAJOR_VERSION >= 3
/* Used in Python 3 only, and even then this function seems to never get
 * called. Python 2 has no module cleanup:
 * http://stackoverflow.com/questions/20741856/run-a-function-when-a-c-extension-module-is-freed-on-python-2
 */
static void do_curlmod_free(void *unused) {
    PyMem_Free(g_pycurl_useragent);
    g_pycurl_useragent = NULL;
}

static PyModuleDef curlmodule = {
    PyModuleDef_HEAD_INIT,
    "pycurl",           /* m_name */
    pycurl_module_doc,  /* m_doc */
    -1,                 /* m_size */
    curl_methods,       /* m_methods */
    NULL,               /* m_reload */
    NULL,               /* m_traverse */
    NULL,               /* m_clear */
    do_curlmod_free     /* m_free */
};
#endif


#if PY_MAJOR_VERSION >= 3
#define PYCURL_MODINIT_RETURN_NULL return NULL
PyMODINIT_FUNC PyInit_pycurl(void)
#else
#define PYCURL_MODINIT_RETURN_NULL return
/* Initialization function for the module */
#if defined(PyMODINIT_FUNC)
PyMODINIT_FUNC
#else
#if defined(__cplusplus)
extern "C"
#endif
DL_EXPORT(void)
#endif
initpycurl(void)
#endif
{
    PyObject *m, *d;
    const curl_version_info_data *vi;
    const char *libcurl_version, *runtime_ssl_lib;
    size_t libcurl_version_len, pycurl_version_len;
    PyObject *xio_module = NULL;
    PyObject *collections_module = NULL;
    PyObject *named_tuple = NULL;
    PyObject *arglist = NULL;

    assert(Curl_Type.tp_weaklistoffset > 0);
    assert(CurlMulti_Type.tp_weaklistoffset > 0);
    assert(CurlShare_Type.tp_weaklistoffset > 0);

    /* Check the version, as this has caused nasty problems in
     * some cases. */
    vi = curl_version_info(CURLVERSION_NOW);
    if (vi == NULL) {
        PyErr_SetString(PyExc_ImportError, "pycurl: curl_version_info() failed");
        goto error;
    }
    if (vi->version_num < LIBCURL_VERSION_NUM) {
        PyErr_Format(PyExc_ImportError, "pycurl: libcurl link-time version (%s) is older than compile-time version (%s)", vi->version, LIBCURL_VERSION);
        goto error;
    }

    /* Our compiled crypto locks should correspond to runtime ssl library. */
    if (vi->ssl_version == NULL) {
        runtime_ssl_lib = "none/other";
    } else if (!strncmp(vi->ssl_version, "OpenSSL/", 8) || !strncmp(vi->ssl_version, "LibreSSL/", 9) ||
               !strncmp(vi->ssl_version, "BoringSSL", 9)) {
        runtime_ssl_lib = "openssl";
    } else if (!strncmp(vi->ssl_version, "wolfSSL/", 8)) {
        runtime_ssl_lib = "wolfssl";
    } else if (!strncmp(vi->ssl_version, "GnuTLS/", 7)) {
        runtime_ssl_lib = "gnutls";
    } else if (!strncmp(vi->ssl_version, "NSS/", 4)) {
        runtime_ssl_lib = "nss";
    } else if (!strncmp(vi->ssl_version, "mbedTLS/", 8)) {
        runtime_ssl_lib = "mbedtls";
    } else {
        runtime_ssl_lib = "none/other";
    }
    if (strcmp(runtime_ssl_lib, COMPILE_SSL_LIB)) {
        PyErr_Format(PyExc_ImportError, "pycurl: libcurl link-time ssl backend (%s) is different from compile-time ssl backend (%s)", runtime_ssl_lib, COMPILE_SSL_LIB);
        goto error;
    }

    /* Initialize the type of the new type objects here; doing it here
     * is required for portability to Windows without requiring C++. */
    p_Curl_Type = &Curl_Type;
    p_CurlMulti_Type = &CurlMulti_Type;
    p_CurlShare_Type = &CurlShare_Type;
    Py_TYPE(&Curl_Type) = &PyType_Type;
    Py_TYPE(&CurlMulti_Type) = &PyType_Type;
    Py_TYPE(&CurlShare_Type) = &PyType_Type;

    /* Create the module and add the functions */
    if (PyType_Ready(&Curl_Type) < 0)
        goto error;

    if (PyType_Ready(&CurlMulti_Type) < 0)
        goto error;

    if (PyType_Ready(&CurlShare_Type) < 0)
        goto error;

#if PY_MAJOR_VERSION >= 3
    m = PyModule_Create(&curlmodule);
    if (m == NULL)
        goto error;
#else
    /* returns a borrowed reference, XDECREFing it crashes the interpreter */
    m = Py_InitModule3("pycurl", curl_methods, pycurl_module_doc);
    if (m == NULL || !PyModule_Check(m))
        goto error;
#endif

    /* Add error object to the module */
    d = PyModule_GetDict(m);
    assert(d != NULL);
    ErrorObject = PyErr_NewException("pycurl.error", NULL, NULL);
    if (ErrorObject == NULL)
        goto error;
    if (PyDict_SetItemString(d, "error", ErrorObject) < 0) {
        goto error;
    }

    curlobject_constants = PyDict_New();
    if (curlobject_constants == NULL)
        goto error;

    curlmultiobject_constants = PyDict_New();
    if (curlmultiobject_constants == NULL)
        goto error;

    curlshareobject_constants = PyDict_New();
    if (curlshareobject_constants == NULL)
        goto error;

    /* Add version strings to the module */
    libcurl_version = curl_version();
    libcurl_version_len = strlen(libcurl_version);
#define PYCURL_VERSION_PREFIX_SIZE sizeof(PYCURL_VERSION_PREFIX)
    /* PYCURL_VERSION_PREFIX_SIZE includes terminating null which will be
     * replaced with the space; libcurl_version_len does not include
     * terminating null. */
    pycurl_version_len = PYCURL_VERSION_PREFIX_SIZE + libcurl_version_len + 1;
    g_pycurl_useragent = PyMem_New(char, pycurl_version_len);
    if (g_pycurl_useragent == NULL)
        goto error;
    memcpy(g_pycurl_useragent, PYCURL_VERSION_PREFIX, PYCURL_VERSION_PREFIX_SIZE);
    g_pycurl_useragent[PYCURL_VERSION_PREFIX_SIZE-1] = ' ';
    memcpy(g_pycurl_useragent + PYCURL_VERSION_PREFIX_SIZE,
        libcurl_version, libcurl_version_len);
    g_pycurl_useragent[pycurl_version_len - 1] = 0;
#undef PYCURL_VERSION_PREFIX_SIZE

    insstr_modinit(d, "version", g_pycurl_useragent);
    insint(d, "COMPILE_PY_VERSION_HEX", PY_VERSION_HEX);
    insint(d, "COMPILE_LIBCURL_VERSION_NUM", LIBCURL_VERSION_NUM);

    /* Types */
    insobj2_modinit(d, NULL, "Curl", (PyObject *) p_Curl_Type);
    insobj2_modinit(d, NULL, "CurlMulti", (PyObject *) p_CurlMulti_Type);
    insobj2_modinit(d, NULL, "CurlShare", (PyObject *) p_CurlShare_Type);

    /**
     ** the order of these constants mostly follows <curl/curl.h>
     **/

    /* Abort curl_read_callback(). */
    insint_c(d, "READFUNC_ABORT", CURL_READFUNC_ABORT);
    insint_c(d, "READFUNC_PAUSE", CURL_READFUNC_PAUSE);

    /* Pause curl_write_callback(). */
    insint_c(d, "WRITEFUNC_PAUSE", CURL_WRITEFUNC_PAUSE);

    /* constants for ioctl callback return values */
    insint_c(d, "IOE_OK", CURLIOE_OK);
    insint_c(d, "IOE_UNKNOWNCMD", CURLIOE_UNKNOWNCMD);
    insint_c(d, "IOE_FAILRESTART", CURLIOE_FAILRESTART);

    /* constants for ioctl callback argument values */
    insint_c(d, "IOCMD_NOP", CURLIOCMD_NOP);
    insint_c(d, "IOCMD_RESTARTREAD", CURLIOCMD_RESTARTREAD);

    /* opensocketfunction return value */
    insint_c(d, "SOCKET_BAD", CURL_SOCKET_BAD);

    /* curl_infotype: the kind of data that is passed to information_callback */
/* XXX do we actually need curl_infotype in pycurl ??? */
    insint_c(d, "INFOTYPE_TEXT", CURLINFO_TEXT);
    insint_c(d, "INFOTYPE_HEADER_IN", CURLINFO_HEADER_IN);
    insint_c(d, "INFOTYPE_HEADER_OUT", CURLINFO_HEADER_OUT);
    insint_c(d, "INFOTYPE_DATA_IN", CURLINFO_DATA_IN);
    insint_c(d, "INFOTYPE_DATA_OUT", CURLINFO_DATA_OUT);
    insint_c(d, "INFOTYPE_SSL_DATA_IN", CURLINFO_SSL_DATA_IN);
    insint_c(d, "INFOTYPE_SSL_DATA_OUT", CURLINFO_SSL_DATA_OUT);

    /* CURLcode: error codes */
    insint_c(d, "E_OK", CURLE_OK);
    insint_c(d, "E_AGAIN", CURLE_AGAIN);
    insint_c(d, "E_ALREADY_COMPLETE", CURLE_ALREADY_COMPLETE);
    insint_c(d, "E_BAD_CALLING_ORDER", CURLE_BAD_CALLING_ORDER);
    insint_c(d, "E_BAD_PASSWORD_ENTERED", CURLE_BAD_PASSWORD_ENTERED);
    insint_c(d, "E_FTP_BAD_DOWNLOAD_RESUME", CURLE_FTP_BAD_DOWNLOAD_RESUME);
    insint_c(d, "E_FTP_COULDNT_SET_TYPE", CURLE_FTP_COULDNT_SET_TYPE);
    insint_c(d, "E_FTP_PARTIAL_FILE", CURLE_FTP_PARTIAL_FILE);
    insint_c(d, "E_FTP_USER_PASSWORD_INCORRECT", CURLE_FTP_USER_PASSWORD_INCORRECT);
    insint_c(d, "E_HTTP_NOT_FOUND", CURLE_HTTP_NOT_FOUND);
    insint_c(d, "E_HTTP_PORT_FAILED", CURLE_HTTP_PORT_FAILED);
    insint_c(d, "E_MALFORMAT_USER", CURLE_MALFORMAT_USER);
    insint_c(d, "E_QUOTE_ERROR", CURLE_QUOTE_ERROR);
    insint_c(d, "E_RANGE_ERROR", CURLE_RANGE_ERROR);
    insint_c(d, "E_REMOTE_ACCESS_DENIED", CURLE_REMOTE_ACCESS_DENIED);
    insint_c(d, "E_REMOTE_DISK_FULL", CURLE_REMOTE_DISK_FULL);
    insint_c(d, "E_REMOTE_FILE_EXISTS", CURLE_REMOTE_FILE_EXISTS);
    insint_c(d, "E_UPLOAD_FAILED", CURLE_UPLOAD_FAILED);
    insint_c(d, "E_URL_MALFORMAT_USER", CURLE_URL_MALFORMAT_USER);
    insint_c(d, "E_USE_SSL_FAILED", CURLE_USE_SSL_FAILED);
    insint_c(d, "E_UNSUPPORTED_PROTOCOL", CURLE_UNSUPPORTED_PROTOCOL);
    insint_c(d, "E_FAILED_INIT", CURLE_FAILED_INIT);
    insint_c(d, "E_URL_MALFORMAT", CURLE_URL_MALFORMAT);
#ifdef HAVE_CURL_7_21_5
    insint_c(d, "E_NOT_BUILT_IN", CURLE_NOT_BUILT_IN);
#endif
    insint_c(d, "E_COULDNT_RESOLVE_PROXY", CURLE_COULDNT_RESOLVE_PROXY);
    insint_c(d, "E_COULDNT_RESOLVE_HOST", CURLE_COULDNT_RESOLVE_HOST);
    insint_c(d, "E_COULDNT_CONNECT", CURLE_COULDNT_CONNECT);
    insint_c(d, "E_FTP_WEIRD_SERVER_REPLY", CURLE_FTP_WEIRD_SERVER_REPLY);
    insint_c(d, "E_FTP_ACCESS_DENIED", CURLE_FTP_ACCESS_DENIED);
#ifdef HAVE_CURL_7_24_0
    insint_c(d, "E_FTP_ACCEPT_FAILED", CURLE_FTP_ACCEPT_FAILED);
#endif
    insint_c(d, "E_FTP_WEIRD_PASS_REPLY", CURLE_FTP_WEIRD_PASS_REPLY);
    insint_c(d, "E_FTP_WEIRD_USER_REPLY", CURLE_FTP_WEIRD_USER_REPLY);
    insint_c(d, "E_FTP_WEIRD_PASV_REPLY", CURLE_FTP_WEIRD_PASV_REPLY);
    insint_c(d, "E_FTP_WEIRD_227_FORMAT", CURLE_FTP_WEIRD_227_FORMAT);
    insint_c(d, "E_FTP_CANT_GET_HOST", CURLE_FTP_CANT_GET_HOST);
    insint_c(d, "E_FTP_CANT_RECONNECT", CURLE_FTP_CANT_RECONNECT);
    insint_c(d, "E_FTP_COULDNT_SET_BINARY", CURLE_FTP_COULDNT_SET_BINARY);
    insint_c(d, "E_PARTIAL_FILE", CURLE_PARTIAL_FILE);
    insint_c(d, "E_FTP_COULDNT_RETR_FILE", CURLE_FTP_COULDNT_RETR_FILE);
    insint_c(d, "E_FTP_WRITE_ERROR", CURLE_FTP_WRITE_ERROR);
    insint_c(d, "E_FTP_QUOTE_ERROR", CURLE_FTP_QUOTE_ERROR);
    insint_c(d, "E_HTTP_RETURNED_ERROR", CURLE_HTTP_RETURNED_ERROR);
    insint_c(d, "E_WRITE_ERROR", CURLE_WRITE_ERROR);
    insint_c(d, "E_FTP_COULDNT_STOR_FILE", CURLE_FTP_COULDNT_STOR_FILE);
    insint_c(d, "E_READ_ERROR", CURLE_READ_ERROR);
    insint_c(d, "E_OUT_OF_MEMORY", CURLE_OUT_OF_MEMORY);
    insint_c(d, "E_OPERATION_TIMEOUTED", CURLE_OPERATION_TIMEOUTED);
    insint_c(d, "E_OPERATION_TIMEDOUT", CURLE_OPERATION_TIMEDOUT);
    insint_c(d, "E_FTP_COULDNT_SET_ASCII", CURLE_FTP_COULDNT_SET_ASCII);
    insint_c(d, "E_FTP_PORT_FAILED", CURLE_FTP_PORT_FAILED);
    insint_c(d, "E_FTP_COULDNT_USE_REST", CURLE_FTP_COULDNT_USE_REST);
    insint_c(d, "E_FTP_COULDNT_GET_SIZE", CURLE_FTP_COULDNT_GET_SIZE);
    insint_c(d, "E_HTTP_RANGE_ERROR", CURLE_HTTP_RANGE_ERROR);
    insint_c(d, "E_HTTP_POST_ERROR", CURLE_HTTP_POST_ERROR);
    insint_c(d, "E_SSL_CACERT", CURLE_SSL_CACERT);
    insint_c(d, "E_SSL_CACERT_BADFILE", CURLE_SSL_CACERT_BADFILE);
    insint_c(d, "E_SSL_CERTPROBLEM", CURLE_SSL_CERTPROBLEM);
    insint_c(d, "E_SSL_CIPHER", CURLE_SSL_CIPHER);
    insint_c(d, "E_SSL_CONNECT_ERROR", CURLE_SSL_CONNECT_ERROR);
    insint_c(d, "E_SSL_CRL_BADFILE", CURLE_SSL_CRL_BADFILE);
    insint_c(d, "E_SSL_ENGINE_INITFAILED", CURLE_SSL_ENGINE_INITFAILED);
    insint_c(d, "E_SSL_ENGINE_NOTFOUND", CURLE_SSL_ENGINE_NOTFOUND);
    insint_c(d, "E_SSL_ENGINE_SETFAILED", CURLE_SSL_ENGINE_SETFAILED);
#if LIBCURL_VERSION_NUM >= MAKE_LIBCURL_VERSION(7, 41, 0)
    insint_c(d, "E_SSL_INVALIDCERTSTATUS", CURLE_SSL_INVALIDCERTSTATUS);
#endif
    insint_c(d, "E_SSL_ISSUER_ERROR", CURLE_SSL_ISSUER_ERROR);
    insint_c(d, "E_SSL_PEER_CERTIFICATE", CURLE_SSL_PEER_CERTIFICATE);
#if LIBCURL_VERSION_NUM >= MAKE_LIBCURL_VERSION(7, 39, 0)
    insint_c(d, "E_SSL_PINNEDPUBKEYNOTMATCH", CURLE_SSL_PINNEDPUBKEYNOTMATCH);
#endif
    insint_c(d, "E_SSL_SHUTDOWN_FAILED", CURLE_SSL_SHUTDOWN_FAILED);
    insint_c(d, "E_BAD_DOWNLOAD_RESUME", CURLE_BAD_DOWNLOAD_RESUME);
    insint_c(d, "E_FILE_COULDNT_READ_FILE", CURLE_FILE_COULDNT_READ_FILE);
    insint_c(d, "E_LDAP_CANNOT_BIND", CURLE_LDAP_CANNOT_BIND);
    insint_c(d, "E_LDAP_SEARCH_FAILED", CURLE_LDAP_SEARCH_FAILED);
    insint_c(d, "E_LIBRARY_NOT_FOUND", CURLE_LIBRARY_NOT_FOUND);
    insint_c(d, "E_FUNCTION_NOT_FOUND", CURLE_FUNCTION_NOT_FOUND);
    insint_c(d, "E_ABORTED_BY_CALLBACK", CURLE_ABORTED_BY_CALLBACK);
    insint_c(d, "E_BAD_FUNCTION_ARGUMENT", CURLE_BAD_FUNCTION_ARGUMENT);
    insint_c(d, "E_INTERFACE_FAILED", CURLE_INTERFACE_FAILED);
    insint_c(d, "E_TOO_MANY_REDIRECTS", CURLE_TOO_MANY_REDIRECTS);
#ifdef HAVE_CURL_7_21_5
    insint_c(d, "E_UNKNOWN_OPTION", CURLE_UNKNOWN_OPTION);
#endif
    /* same as E_UNKNOWN_OPTION */
    insint_c(d, "E_UNKNOWN_TELNET_OPTION", CURLE_UNKNOWN_TELNET_OPTION);
    insint_c(d, "E_TELNET_OPTION_SYNTAX", CURLE_TELNET_OPTION_SYNTAX);
    insint_c(d, "E_GOT_NOTHING", CURLE_GOT_NOTHING);
    insint_c(d, "E_SEND_ERROR", CURLE_SEND_ERROR);
    insint_c(d, "E_RECV_ERROR", CURLE_RECV_ERROR);
    insint_c(d, "E_SHARE_IN_USE", CURLE_SHARE_IN_USE);
    insint_c(d, "E_BAD_CONTENT_ENCODING", CURLE_BAD_CONTENT_ENCODING);
    insint_c(d, "E_LDAP_INVALID_URL", CURLE_LDAP_INVALID_URL);
    insint_c(d, "E_FILESIZE_EXCEEDED", CURLE_FILESIZE_EXCEEDED);
    insint_c(d, "E_FTP_SSL_FAILED", CURLE_FTP_SSL_FAILED);
    insint_c(d, "E_SEND_FAIL_REWIND", CURLE_SEND_FAIL_REWIND);
    insint_c(d, "E_LOGIN_DENIED", CURLE_LOGIN_DENIED);
    insint_c(d, "E_PEER_FAILED_VERIFICATION", CURLE_PEER_FAILED_VERIFICATION);
    insint_c(d, "E_TFTP_NOTFOUND", CURLE_TFTP_NOTFOUND);
    insint_c(d, "E_TFTP_PERM", CURLE_TFTP_PERM);
    insint_c(d, "E_TFTP_DISKFULL", CURLE_TFTP_DISKFULL);
    insint_c(d, "E_TFTP_ILLEGAL", CURLE_TFTP_ILLEGAL);
    insint_c(d, "E_TFTP_UNKNOWNID", CURLE_TFTP_UNKNOWNID);
    insint_c(d, "E_TFTP_EXISTS", CURLE_TFTP_EXISTS);
    insint_c(d, "E_TFTP_NOSUCHUSER", CURLE_TFTP_NOSUCHUSER);
    insint_c(d, "E_CONV_FAILED", CURLE_CONV_FAILED);
    insint_c(d, "E_CONV_REQD", CURLE_CONV_REQD);
    insint_c(d, "E_REMOTE_FILE_NOT_FOUND", CURLE_REMOTE_FILE_NOT_FOUND);
    insint_c(d, "E_SSH", CURLE_SSH);
#if LIBCURL_VERSION_NUM >= MAKE_LIBCURL_VERSION(7, 20, 0)
    insint_c(d, "E_FTP_PRET_FAILED", CURLE_FTP_PRET_FAILED);
    insint_c(d, "E_RTSP_CSEQ_ERROR", CURLE_RTSP_CSEQ_ERROR);
    insint_c(d, "E_RTSP_SESSION_ERROR", CURLE_RTSP_SESSION_ERROR);
#endif
#if LIBCURL_VERSION_NUM >= MAKE_LIBCURL_VERSION(7, 21, 0)
    insint_c(d, "E_CHUNK_FAILED", CURLE_CHUNK_FAILED);
    insint_c(d, "E_FTP_BAD_FILE_LIST", CURLE_FTP_BAD_FILE_LIST);
#endif
#if LIBCURL_VERSION_NUM >= MAKE_LIBCURL_VERSION(7, 24, 0)
    insint_c(d, "E_FTP_ACCEPT_TIMEOUT", CURLE_FTP_ACCEPT_TIMEOUT);
#endif
#if LIBCURL_VERSION_NUM >= MAKE_LIBCURL_VERSION(7, 30, 0)
    insint_c(d, "E_NO_CONNECTION_AVAILABLE", CURLE_NO_CONNECTION_AVAILABLE);
#endif
#if LIBCURL_VERSION_NUM >= MAKE_LIBCURL_VERSION(7, 38, 0)
    insint_c(d, "E_HTTP2", CURLE_HTTP2);
#endif

    /* curl_proxytype: constants for setopt(PROXYTYPE, x) */
    insint_c(d, "PROXYTYPE_HTTP", CURLPROXY_HTTP);
#ifdef HAVE_CURL_7_19_4_OPTS
    insint_c(d, "PROXYTYPE_HTTP_1_0", CURLPROXY_HTTP_1_0);
#endif
    insint_c(d, "PROXYTYPE_SOCKS4", CURLPROXY_SOCKS4);
    insint_c(d, "PROXYTYPE_SOCKS4A", CURLPROXY_SOCKS4A);
    insint_c(d, "PROXYTYPE_SOCKS5", CURLPROXY_SOCKS5);
    insint_c(d, "PROXYTYPE_SOCKS5_HOSTNAME", CURLPROXY_SOCKS5_HOSTNAME);

    /* curl_httpauth: constants for setopt(HTTPAUTH, x) */
    insint_c(d, "HTTPAUTH_ANY", CURLAUTH_ANY);
    insint_c(d, "HTTPAUTH_ANYSAFE", CURLAUTH_ANYSAFE);
    insint_c(d, "HTTPAUTH_BASIC", CURLAUTH_BASIC);
    insint_c(d, "HTTPAUTH_DIGEST", CURLAUTH_DIGEST);
#ifdef HAVE_CURLAUTH_DIGEST_IE
    insint_c(d, "HTTPAUTH_DIGEST_IE", CURLAUTH_DIGEST_IE);
#endif
    insint_c(d, "HTTPAUTH_GSSNEGOTIATE", CURLAUTH_GSSNEGOTIATE);
#if LIBCURL_VERSION_NUM >= MAKE_LIBCURL_VERSION(7, 38, 0)
    insint_c(d, "HTTPAUTH_NEGOTIATE", CURLAUTH_NEGOTIATE);
#endif
    insint_c(d, "HTTPAUTH_NTLM", CURLAUTH_NTLM);
#if LIBCURL_VERSION_NUM >= MAKE_LIBCURL_VERSION(7, 22, 0)
    insint_c(d, "HTTPAUTH_NTLM_WB", CURLAUTH_NTLM_WB);
#endif
    insint_c(d, "HTTPAUTH_NONE", CURLAUTH_NONE);
#if LIBCURL_VERSION_NUM >= MAKE_LIBCURL_VERSION(7, 21, 3)
    insint_c(d, "HTTPAUTH_ONLY", CURLAUTH_ONLY);
#endif

#ifdef HAVE_CURL_7_22_0_OPTS
    insint_c(d, "GSSAPI_DELEGATION_FLAG", CURLGSSAPI_DELEGATION_FLAG);
    insint_c(d, "GSSAPI_DELEGATION_NONE", CURLGSSAPI_DELEGATION_NONE);
    insint_c(d, "GSSAPI_DELEGATION_POLICY_FLAG", CURLGSSAPI_DELEGATION_POLICY_FLAG);

    insint_c(d, "GSSAPI_DELEGATION", CURLOPT_GSSAPI_DELEGATION);
#endif

    /* curl_ftpssl: constants for setopt(FTP_SSL, x) */
    insint_c(d, "FTPSSL_NONE", CURLFTPSSL_NONE);
    insint_c(d, "FTPSSL_TRY", CURLFTPSSL_TRY);
    insint_c(d, "FTPSSL_CONTROL", CURLFTPSSL_CONTROL);
    insint_c(d, "FTPSSL_ALL", CURLFTPSSL_ALL);

    /* curl_ftpauth: constants for setopt(FTPSSLAUTH, x) */
    insint_c(d, "FTPAUTH_DEFAULT", CURLFTPAUTH_DEFAULT);
    insint_c(d, "FTPAUTH_SSL", CURLFTPAUTH_SSL);
    insint_c(d, "FTPAUTH_TLS", CURLFTPAUTH_TLS);

    /* curl_ftpauth: constants for setopt(FTPSSLAUTH, x) */
    insint_c(d, "FORM_BUFFER", CURLFORM_BUFFER);
    insint_c(d, "FORM_BUFFERPTR", CURLFORM_BUFFERPTR);
    insint_c(d, "FORM_CONTENTS", CURLFORM_COPYCONTENTS);
    insint_c(d, "FORM_FILE", CURLFORM_FILE);
    insint_c(d, "FORM_CONTENTTYPE", CURLFORM_CONTENTTYPE);
    insint_c(d, "FORM_FILENAME", CURLFORM_FILENAME);

    /* FTP_FILEMETHOD options */
    insint_c(d, "FTPMETHOD_DEFAULT", CURLFTPMETHOD_DEFAULT);
    insint_c(d, "FTPMETHOD_MULTICWD", CURLFTPMETHOD_MULTICWD);
    insint_c(d, "FTPMETHOD_NOCWD", CURLFTPMETHOD_NOCWD);
    insint_c(d, "FTPMETHOD_SINGLECWD", CURLFTPMETHOD_SINGLECWD);

    /* CURLoption: symbolic constants for setopt() */
    insint_c(d, "APPEND", CURLOPT_APPEND);
    insint_c(d, "COOKIESESSION", CURLOPT_COOKIESESSION);
    insint_c(d, "DIRLISTONLY", CURLOPT_DIRLISTONLY);
    /* ERRORBUFFER is not supported */
    insint_c(d, "FILE", CURLOPT_WRITEDATA);
    insint_c(d, "FTPPORT", CURLOPT_FTPPORT);
    insint_c(d, "INFILE", CURLOPT_READDATA);
    insint_c(d, "INFILESIZE", CURLOPT_INFILESIZE_LARGE);    /* _LARGE ! */
    insint_c(d, "KEYPASSWD", CURLOPT_KEYPASSWD);
    insint_c(d, "LOW_SPEED_LIMIT", CURLOPT_LOW_SPEED_LIMIT);
    insint_c(d, "LOW_SPEED_TIME", CURLOPT_LOW_SPEED_TIME);
    insint_c(d, "PORT", CURLOPT_PORT);
    insint_c(d, "POSTFIELDS", CURLOPT_POSTFIELDS);
    insint_c(d, "PROXY", CURLOPT_PROXY);
#ifdef HAVE_CURLOPT_PROXYUSERNAME
    insint_c(d, "PROXYPASSWORD", CURLOPT_PROXYPASSWORD);
    insint_c(d, "PROXYUSERNAME", CURLOPT_PROXYUSERNAME);
#endif
    insint_c(d, "PROXYUSERPWD", CURLOPT_PROXYUSERPWD);
    insint_c(d, "RANGE", CURLOPT_RANGE);
    insint_c(d, "READFUNCTION", CURLOPT_READFUNCTION);
    insint_c(d, "REFERER", CURLOPT_REFERER);
    insint_c(d, "RESUME_FROM", CURLOPT_RESUME_FROM_LARGE);  /* _LARGE ! */
    insint_c(d, "TELNETOPTIONS", CURLOPT_TELNETOPTIONS);
    insint_c(d, "TIMEOUT", CURLOPT_TIMEOUT);
    insint_c(d, "URL", CURLOPT_URL);
    insint_c(d, "USE_SSL", CURLOPT_USE_SSL);
    insint_c(d, "USERAGENT", CURLOPT_USERAGENT);
    insint_c(d, "USERPWD", CURLOPT_USERPWD);
    insint_c(d, "WRITEFUNCTION", CURLOPT_WRITEFUNCTION);
#if LIBCURL_VERSION_NUM >= MAKE_LIBCURL_VERSION(7, 20, 0)
    insint_c(d, "OPT_RTSP_CLIENT_CSEQ", CURLOPT_RTSP_CLIENT_CSEQ);
    insint_c(d, "OPT_RTSP_REQUEST", CURLOPT_RTSP_REQUEST);
    insint_c(d, "OPT_RTSP_SERVER_CSEQ", CURLOPT_RTSP_SERVER_CSEQ);
    insint_c(d, "OPT_RTSP_SESSION_ID", CURLOPT_RTSP_SESSION_ID);
    insint_c(d, "OPT_RTSP_STREAM_URI", CURLOPT_RTSP_STREAM_URI);
    insint_c(d, "OPT_RTSP_TRANSPORT", CURLOPT_RTSP_TRANSPORT);
#endif
#ifdef HAVE_CURLOPT_USERNAME
    insint_c(d, "USERNAME", CURLOPT_USERNAME);
    insint_c(d, "PASSWORD", CURLOPT_PASSWORD);
#endif
    insint_c(d, "WRITEDATA", CURLOPT_WRITEDATA);
    insint_c(d, "READDATA", CURLOPT_READDATA);
    insint_c(d, "PROXYPORT", CURLOPT_PROXYPORT);
    insint_c(d, "HTTPPROXYTUNNEL", CURLOPT_HTTPPROXYTUNNEL);
    insint_c(d, "VERBOSE", CURLOPT_VERBOSE);
    insint_c(d, "HEADER", CURLOPT_HEADER);
    insint_c(d, "NOPROGRESS", CURLOPT_NOPROGRESS);
    insint_c(d, "NOBODY", CURLOPT_NOBODY);
    insint_c(d, "FAILONERROR", CURLOPT_FAILONERROR);
    insint_c(d, "UPLOAD", CURLOPT_UPLOAD);
    insint_c(d, "POST", CURLOPT_POST);
    insint_c(d, "FTPLISTONLY", CURLOPT_FTPLISTONLY);
    insint_c(d, "FTPAPPEND", CURLOPT_FTPAPPEND);
    insint_c(d, "NETRC", CURLOPT_NETRC);
    insint_c(d, "FOLLOWLOCATION", CURLOPT_FOLLOWLOCATION);
    insint_c(d, "TRANSFERTEXT", CURLOPT_TRANSFERTEXT);
    insint_c(d, "PUT", CURLOPT_PUT);
    insint_c(d, "POSTFIELDSIZE", CURLOPT_POSTFIELDSIZE_LARGE);  /* _LARGE ! */
    insint_c(d, "COOKIE", CURLOPT_COOKIE);
    insint_c(d, "HTTPHEADER", CURLOPT_HTTPHEADER);
#if LIBCURL_VERSION_NUM >= MAKE_LIBCURL_VERSION(7, 37, 0)
    insint_c(d, "PROXYHEADER", CURLOPT_PROXYHEADER);
    insint_c(d, "HEADEROPT", CURLOPT_HEADEROPT);
#endif
#if LIBCURL_VERSION_NUM >= MAKE_LIBCURL_VERSION(7, 42, 0)
    insint_c(d, "PATH_AS_IS", CURLOPT_PATH_AS_IS);
#endif
#if LIBCURL_VERSION_NUM >= MAKE_LIBCURL_VERSION(7, 43, 0)
    insint_c(d, "PIPEWAIT", CURLOPT_PIPEWAIT);
#endif
    insint_c(d, "HTTPPOST", CURLOPT_HTTPPOST);
    insint_c(d, "SSLCERT", CURLOPT_SSLCERT);
    insint_c(d, "SSLCERTPASSWD", CURLOPT_SSLCERTPASSWD);
    insint_c(d, "CRLF", CURLOPT_CRLF);
    insint_c(d, "QUOTE", CURLOPT_QUOTE);
    insint_c(d, "POSTQUOTE", CURLOPT_POSTQUOTE);
    insint_c(d, "PREQUOTE", CURLOPT_PREQUOTE);
    insint_c(d, "WRITEHEADER", CURLOPT_WRITEHEADER);
    insint_c(d, "HEADERFUNCTION", CURLOPT_HEADERFUNCTION);
    insint_c(d, "SEEKFUNCTION", CURLOPT_SEEKFUNCTION);
    insint_c(d, "COOKIEFILE", CURLOPT_COOKIEFILE);
    insint_c(d, "SSLVERSION", CURLOPT_SSLVERSION);
    insint_c(d, "TIMECONDITION", CURLOPT_TIMECONDITION);
    insint_c(d, "TIMEVALUE", CURLOPT_TIMEVALUE);
    insint_c(d, "CUSTOMREQUEST", CURLOPT_CUSTOMREQUEST);
    insint_c(d, "STDERR", CURLOPT_STDERR);
    insint_c(d, "INTERFACE", CURLOPT_INTERFACE);
    insint_c(d, "KRB4LEVEL", CURLOPT_KRB4LEVEL);
    insint_c(d, "KRBLEVEL", CURLOPT_KRBLEVEL);
    insint_c(d, "PROGRESSFUNCTION", CURLOPT_PROGRESSFUNCTION);
#if LIBCURL_VERSION_NUM >= MAKE_LIBCURL_VERSION(7, 32, 0)
    insint_c(d, "XFERINFOFUNCTION", CURLOPT_XFERINFOFUNCTION);
#endif
#if LIBCURL_VERSION_NUM >= MAKE_LIBCURL_VERSION(7, 20, 0)
    insint_c(d, "FTP_USE_PRET", CURLOPT_FTP_USE_PRET);
#endif
#if LIBCURL_VERSION_NUM >= MAKE_LIBCURL_VERSION(7, 34, 0)
    insint_c(d, "LOGIN_OPTIONS", CURLOPT_LOGIN_OPTIONS);
#endif
#if LIBCURL_VERSION_NUM >= MAKE_LIBCURL_VERSION(7, 31, 0)
    insint_c(d, "SASL_IR", CURLOPT_SASL_IR);
#endif
#if LIBCURL_VERSION_NUM >= MAKE_LIBCURL_VERSION(7, 33, 0)
    insint_c(d, "XOAUTH2_BEARER", CURLOPT_XOAUTH2_BEARER);
#endif
    insint_c(d, "SSL_VERIFYPEER", CURLOPT_SSL_VERIFYPEER);
    insint_c(d, "CAPATH", CURLOPT_CAPATH);
    insint_c(d, "CAINFO", CURLOPT_CAINFO);
    insint_c(d, "OPT_FILETIME", CURLOPT_FILETIME);
    insint_c(d, "MAXREDIRS", CURLOPT_MAXREDIRS);
    insint_c(d, "MAXCONNECTS", CURLOPT_MAXCONNECTS);
    insint_c(d, "FRESH_CONNECT", CURLOPT_FRESH_CONNECT);
    insint_c(d, "FORBID_REUSE", CURLOPT_FORBID_REUSE);
    insint_c(d, "RANDOM_FILE", CURLOPT_RANDOM_FILE);
    insint_c(d, "EGDSOCKET", CURLOPT_EGDSOCKET);
    insint_c(d, "CONNECTTIMEOUT", CURLOPT_CONNECTTIMEOUT);
    insint_c(d, "HTTPGET", CURLOPT_HTTPGET);
    insint_c(d, "SSL_VERIFYHOST", CURLOPT_SSL_VERIFYHOST);
    insint_c(d, "COOKIEJAR", CURLOPT_COOKIEJAR);
    insint_c(d, "SSL_CIPHER_LIST", CURLOPT_SSL_CIPHER_LIST);
    insint_c(d, "HTTP_VERSION", CURLOPT_HTTP_VERSION);
    insint_c(d, "FTP_USE_EPSV", CURLOPT_FTP_USE_EPSV);
    insint_c(d, "SSLCERTTYPE", CURLOPT_SSLCERTTYPE);
    insint_c(d, "SSLKEY", CURLOPT_SSLKEY);
    insint_c(d, "SSLKEYTYPE", CURLOPT_SSLKEYTYPE);
    /* same as CURLOPT_KEYPASSWD */
    insint_c(d, "SSLKEYPASSWD", CURLOPT_SSLKEYPASSWD);
    insint_c(d, "SSLENGINE", CURLOPT_SSLENGINE);
    insint_c(d, "SSLENGINE_DEFAULT", CURLOPT_SSLENGINE_DEFAULT);
    insint_c(d, "DNS_CACHE_TIMEOUT", CURLOPT_DNS_CACHE_TIMEOUT);
    insint_c(d, "DNS_USE_GLOBAL_CACHE", CURLOPT_DNS_USE_GLOBAL_CACHE);
    insint_c(d, "DEBUGFUNCTION", CURLOPT_DEBUGFUNCTION);
    insint_c(d, "BUFFERSIZE", CURLOPT_BUFFERSIZE);
    insint_c(d, "NOSIGNAL", CURLOPT_NOSIGNAL);
    insint_c(d, "SHARE", CURLOPT_SHARE);
    insint_c(d, "PROXYTYPE", CURLOPT_PROXYTYPE);
    /* superseded by ACCEPT_ENCODING */
    insint_c(d, "ENCODING", CURLOPT_ENCODING);
#if LIBCURL_VERSION_NUM >= MAKE_LIBCURL_VERSION(7, 21, 6)
    insint_c(d, "ACCEPT_ENCODING", CURLOPT_ACCEPT_ENCODING);
    insint_c(d, "TRANSFER_ENCODING", CURLOPT_TRANSFER_ENCODING);
#endif
    insint_c(d, "HTTP200ALIASES", CURLOPT_HTTP200ALIASES);
    insint_c(d, "UNRESTRICTED_AUTH", CURLOPT_UNRESTRICTED_AUTH);
    insint_c(d, "FTP_USE_EPRT", CURLOPT_FTP_USE_EPRT);
    insint_c(d, "HTTPAUTH", CURLOPT_HTTPAUTH);
    insint_c(d, "FTP_CREATE_MISSING_DIRS", CURLOPT_FTP_CREATE_MISSING_DIRS);
    insint_c(d, "PROXYAUTH", CURLOPT_PROXYAUTH);
    insint_c(d, "FTP_RESPONSE_TIMEOUT", CURLOPT_FTP_RESPONSE_TIMEOUT);
    insint_c(d, "IPRESOLVE", CURLOPT_IPRESOLVE);
    insint_c(d, "MAXFILESIZE", CURLOPT_MAXFILESIZE_LARGE);  /* _LARGE ! */
    insint_c(d, "INFILESIZE_LARGE", CURLOPT_INFILESIZE_LARGE);
    insint_c(d, "RESUME_FROM_LARGE", CURLOPT_RESUME_FROM_LARGE);
    insint_c(d, "MAXFILESIZE_LARGE", CURLOPT_MAXFILESIZE_LARGE);
    insint_c(d, "NETRC_FILE", CURLOPT_NETRC_FILE);
    insint_c(d, "FTP_SSL", CURLOPT_FTP_SSL);
    insint_c(d, "POSTFIELDSIZE_LARGE", CURLOPT_POSTFIELDSIZE_LARGE);
    insint_c(d, "TCP_NODELAY", CURLOPT_TCP_NODELAY);
    insint_c(d, "FTPSSLAUTH", CURLOPT_FTPSSLAUTH);
    insint_c(d, "IOCTLFUNCTION", CURLOPT_IOCTLFUNCTION);
    insint_c(d, "OPENSOCKETFUNCTION", CURLOPT_OPENSOCKETFUNCTION);
#if LIBCURL_VERSION_NUM >= MAKE_LIBCURL_VERSION(7, 21, 7)
    insint_c(d, "CLOSESOCKETFUNCTION", CURLOPT_CLOSESOCKETFUNCTION);
#endif
    insint_c(d, "SOCKOPTFUNCTION", CURLOPT_SOCKOPTFUNCTION);
    insint_c(d, "FTP_ACCOUNT", CURLOPT_FTP_ACCOUNT);
    insint_c(d, "IGNORE_CONTENT_LENGTH", CURLOPT_IGNORE_CONTENT_LENGTH);
    insint_c(d, "COOKIELIST", CURLOPT_COOKIELIST);
    insint_c(d, "OPT_COOKIELIST", CURLOPT_COOKIELIST);
    insint_c(d, "FTP_SKIP_PASV_IP", CURLOPT_FTP_SKIP_PASV_IP);
    insint_c(d, "FTP_FILEMETHOD", CURLOPT_FTP_FILEMETHOD);
    insint_c(d, "CONNECT_ONLY", CURLOPT_CONNECT_ONLY);
    insint_c(d, "LOCALPORT", CURLOPT_LOCALPORT);
    insint_c(d, "LOCALPORTRANGE", CURLOPT_LOCALPORTRANGE);
    insint_c(d, "FTP_ALTERNATIVE_TO_USER", CURLOPT_FTP_ALTERNATIVE_TO_USER);
    insint_c(d, "MAX_SEND_SPEED_LARGE", CURLOPT_MAX_SEND_SPEED_LARGE);
    insint_c(d, "MAX_RECV_SPEED_LARGE", CURLOPT_MAX_RECV_SPEED_LARGE);
    insint_c(d, "SSL_SESSIONID_CACHE", CURLOPT_SSL_SESSIONID_CACHE);
#if LIBCURL_VERSION_NUM >= MAKE_LIBCURL_VERSION(7, 41, 0)
    insint_c(d, "SSL_VERIFYSTATUS", CURLOPT_SSL_VERIFYSTATUS);
#endif
    insint_c(d, "SSH_AUTH_TYPES", CURLOPT_SSH_AUTH_TYPES);
    insint_c(d, "SSH_PUBLIC_KEYFILE", CURLOPT_SSH_PUBLIC_KEYFILE);
    insint_c(d, "SSH_PRIVATE_KEYFILE", CURLOPT_SSH_PRIVATE_KEYFILE);
#ifdef HAVE_CURL_7_19_6_OPTS
    insint_c(d, "SSH_KNOWNHOSTS", CURLOPT_SSH_KNOWNHOSTS);
    insint_c(d, "SSH_KEYFUNCTION", CURLOPT_SSH_KEYFUNCTION);
#endif
    insint_c(d, "FTP_SSL_CCC", CURLOPT_FTP_SSL_CCC);
    insint_c(d, "TIMEOUT_MS", CURLOPT_TIMEOUT_MS);
    insint_c(d, "CONNECTTIMEOUT_MS", CURLOPT_CONNECTTIMEOUT_MS);
#if LIBCURL_VERSION_NUM >= MAKE_LIBCURL_VERSION(7, 24, 0)
    insint_c(d, "ACCEPTTIMEOUT_MS", CURLOPT_ACCEPTTIMEOUT_MS);
#endif
#if LIBCURL_VERSION_NUM >= MAKE_LIBCURL_VERSION(7, 36, 0)
    insint_c(d, "EXPECT_100_TIMEOUT_MS", CURLOPT_EXPECT_100_TIMEOUT_MS);
#endif
#if LIBCURL_VERSION_NUM >= MAKE_LIBCURL_VERSION(7, 25, 0)
    insint_c(d, "TCP_KEEPALIVE", CURLOPT_TCP_KEEPALIVE);
    insint_c(d, "TCP_KEEPIDLE", CURLOPT_TCP_KEEPIDLE);
    insint_c(d, "TCP_KEEPINTVL", CURLOPT_TCP_KEEPINTVL);
#endif
    insint_c(d, "HTTP_TRANSFER_DECODING", CURLOPT_HTTP_TRANSFER_DECODING);
    insint_c(d, "HTTP_CONTENT_DECODING", CURLOPT_HTTP_CONTENT_DECODING);
    insint_c(d, "NEW_FILE_PERMS", CURLOPT_NEW_FILE_PERMS);
    insint_c(d, "NEW_DIRECTORY_PERMS", CURLOPT_NEW_DIRECTORY_PERMS);
    insint_c(d, "POST301", CURLOPT_POST301);
    insint_c(d, "PROXY_TRANSFER_MODE", CURLOPT_PROXY_TRANSFER_MODE);
#if LIBCURL_VERSION_NUM >= MAKE_LIBCURL_VERSION(7, 43, 0)
    insint_c(d, "SERVICE_NAME", CURLOPT_SERVICE_NAME);
    insint_c(d, "PROXY_SERVICE_NAME", CURLOPT_PROXY_SERVICE_NAME);
#endif
#if LIBCURL_VERSION_NUM >= MAKE_LIBCURL_VERSION(7, 52, 0)
    insint_c(d, "PROXY_CAPATH", CURLOPT_PROXY_CAPATH);
    insint_c(d, "PROXY_CAINFO", CURLOPT_PROXY_CAINFO);
    insint_c(d, "PRE_PROXY", CURLOPT_PRE_PROXY);
    insint_c(d, "PROXY_SSLCERT", CURLOPT_PROXY_SSLCERT);
    insint_c(d, "PROXY_SSLCERTTYPE", CURLOPT_PROXY_SSLCERTTYPE);
    insint_c(d, "PROXY_SSLKEY", CURLOPT_PROXY_SSLKEY);
    insint_c(d, "PROXY_SSLKEYTYPE", CURLOPT_PROXY_SSLKEYTYPE);
    insint_c(d, "PROXY_SSL_VERIFYPEER", CURLOPT_PROXY_SSL_VERIFYPEER);
    insint_c(d, "PROXY_SSL_VERIFYHOST", CURLOPT_PROXY_SSL_VERIFYHOST);
#endif
    insint_c(d, "COPYPOSTFIELDS", CURLOPT_COPYPOSTFIELDS);
    insint_c(d, "SSH_HOST_PUBLIC_KEY_MD5", CURLOPT_SSH_HOST_PUBLIC_KEY_MD5);
    insint_c(d, "AUTOREFERER", CURLOPT_AUTOREFERER);
    insint_c(d, "CRLFILE", CURLOPT_CRLFILE);
    insint_c(d, "ISSUERCERT", CURLOPT_ISSUERCERT);
    insint_c(d, "ADDRESS_SCOPE", CURLOPT_ADDRESS_SCOPE);
#ifdef HAVE_CURLOPT_RESOLVE
    insint_c(d, "RESOLVE", CURLOPT_RESOLVE);
#endif
#ifdef HAVE_CURLOPT_CERTINFO
    insint_c(d, "OPT_CERTINFO", CURLOPT_CERTINFO);
#endif
#ifdef HAVE_CURLOPT_POSTREDIR
    insint_c(d, "POSTREDIR", CURLOPT_POSTREDIR);
#endif
#ifdef HAVE_CURLOPT_NOPROXY
    insint_c(d, "NOPROXY", CURLOPT_NOPROXY);
#endif
#ifdef HAVE_CURLOPT_PROTOCOLS
    insint_c(d, "PROTOCOLS", CURLOPT_PROTOCOLS);
    insint_c(d, "REDIR_PROTOCOLS", CURLOPT_REDIR_PROTOCOLS);
    insint_c(d, "PROTO_HTTP", CURLPROTO_HTTP);
    insint_c(d, "PROTO_HTTPS", CURLPROTO_HTTPS);
    insint_c(d, "PROTO_FTP", CURLPROTO_FTP);
    insint_c(d, "PROTO_FTPS", CURLPROTO_FTPS);
    insint_c(d, "PROTO_SCP", CURLPROTO_SCP);
    insint_c(d, "PROTO_SFTP", CURLPROTO_SFTP);
    insint_c(d, "PROTO_TELNET", CURLPROTO_TELNET);
    insint_c(d, "PROTO_LDAP", CURLPROTO_LDAP);
    insint_c(d, "PROTO_LDAPS", CURLPROTO_LDAPS);
    insint_c(d, "PROTO_DICT", CURLPROTO_DICT);
    insint_c(d, "PROTO_FILE", CURLPROTO_FILE);
    insint_c(d, "PROTO_TFTP", CURLPROTO_TFTP);
#ifdef HAVE_CURL_7_20_0_OPTS
    insint_c(d, "PROTO_IMAP", CURLPROTO_IMAP);
    insint_c(d, "PROTO_IMAPS", CURLPROTO_IMAPS);
    insint_c(d, "PROTO_POP3", CURLPROTO_POP3);
    insint_c(d, "PROTO_POP3S", CURLPROTO_POP3S);
    insint_c(d, "PROTO_SMTP", CURLPROTO_SMTP);
    insint_c(d, "PROTO_SMTPS", CURLPROTO_SMTPS);
#endif
#ifdef HAVE_CURL_7_21_0_OPTS
    insint_c(d, "PROTO_RTSP", CURLPROTO_RTSP);
    insint_c(d, "PROTO_RTMP", CURLPROTO_RTMP);
    insint_c(d, "PROTO_RTMPT", CURLPROTO_RTMPT);
    insint_c(d, "PROTO_RTMPE", CURLPROTO_RTMPE);
    insint_c(d, "PROTO_RTMPTE", CURLPROTO_RTMPTE);
    insint_c(d, "PROTO_RTMPS", CURLPROTO_RTMPS);
    insint_c(d, "PROTO_RTMPTS", CURLPROTO_RTMPTS);
#endif
#ifdef HAVE_CURL_7_21_2_OPTS
    insint_c(d, "PROTO_GOPHER", CURLPROTO_GOPHER);
#endif
#if LIBCURL_VERSION_NUM >= MAKE_LIBCURL_VERSION(7, 40, 0)
    insint_c(d, "PROTO_SMB", CURLPROTO_SMB);
    insint_c(d, "PROTO_SMBS", CURLPROTO_SMBS);
#endif
    insint_c(d, "PROTO_ALL", CURLPROTO_ALL);
#endif
#ifdef HAVE_CURL_7_19_4_OPTS
    insint_c(d, "TFTP_BLKSIZE", CURLOPT_TFTP_BLKSIZE);
    insint_c(d, "SOCKS5_GSSAPI_SERVICE", CURLOPT_SOCKS5_GSSAPI_SERVICE);
    insint_c(d, "SOCKS5_GSSAPI_NEC", CURLOPT_SOCKS5_GSSAPI_NEC);
#endif
#ifdef HAVE_CURL_7_20_0_OPTS
    insint_c(d, "MAIL_FROM", CURLOPT_MAIL_FROM);
    insint_c(d, "MAIL_RCPT", CURLOPT_MAIL_RCPT);
#endif
#ifdef HAVE_CURL_7_25_0_OPTS
    insint_c(d, "MAIL_AUTH", CURLOPT_MAIL_AUTH);
#endif
#if LIBCURL_VERSION_NUM >= MAKE_LIBCURL_VERSION(7, 39, 0)
    insint_c(d, "PINNEDPUBLICKEY", CURLOPT_PINNEDPUBLICKEY);
#endif
#if LIBCURL_VERSION_NUM >= MAKE_LIBCURL_VERSION(7, 21, 0)
    insint_c(d, "WILDCARDMATCH", CURLOPT_WILDCARDMATCH);
#endif
#if LIBCURL_VERSION_NUM >= MAKE_LIBCURL_VERSION(7, 40, 0)
    insint_c(d, "UNIX_SOCKET_PATH", CURLOPT_UNIX_SOCKET_PATH);
#endif
#if LIBCURL_VERSION_NUM >= MAKE_LIBCURL_VERSION(7, 36, 0)
    insint_c(d, "SSL_ENABLE_ALPN", CURLOPT_SSL_ENABLE_ALPN);
    insint_c(d, "SSL_ENABLE_NPN", CURLOPT_SSL_ENABLE_NPN);
#endif
#if LIBCURL_VERSION_NUM >= MAKE_LIBCURL_VERSION(7, 42, 0)
    insint_c(d, "SSL_FALSESTART", CURLOPT_SSL_FALSESTART);
#endif
#if LIBCURL_VERSION_NUM >= MAKE_LIBCURL_VERSION(7, 25, 0)
    insint_c(d, "SSL_OPTIONS", CURLOPT_SSL_OPTIONS);
    insint_c(d, "SSLOPT_ALLOW_BEAST", CURLSSLOPT_ALLOW_BEAST);
# if LIBCURL_VERSION_NUM >= MAKE_LIBCURL_VERSION(7, 44, 0)
    insint_c(d, "SSLOPT_NO_REVOKE", CURLSSLOPT_NO_REVOKE);
# endif
#endif
#if LIBCURL_VERSION_NUM >= MAKE_LIBCURL_VERSION(7, 21, 4)
    insint_c(d, "TLSAUTH_TYPE", CURLOPT_TLSAUTH_TYPE);
    insint_c(d, "TLSAUTH_USERNAME", CURLOPT_TLSAUTH_USERNAME);
    insint_c(d, "TLSAUTH_PASSWORD", CURLOPT_TLSAUTH_PASSWORD);
#endif
#if LIBCURL_VERSION_NUM >= MAKE_LIBCURL_VERSION(7, 45, 0)
    insint_c(d, "DEFAULT_PROTOCOL", CURLOPT_DEFAULT_PROTOCOL);
#endif

    insint_m(d, "M_TIMERFUNCTION", CURLMOPT_TIMERFUNCTION);
    insint_m(d, "M_SOCKETFUNCTION", CURLMOPT_SOCKETFUNCTION);
    insint_m(d, "M_PIPELINING", CURLMOPT_PIPELINING);
    insint_m(d, "M_MAXCONNECTS", CURLMOPT_MAXCONNECTS);
#ifdef HAVE_CURL_7_30_0_PIPELINE_OPTS
    insint_m(d, "M_MAX_HOST_CONNECTIONS", CURLMOPT_MAX_HOST_CONNECTIONS);
    insint_m(d, "M_MAX_TOTAL_CONNECTIONS", CURLMOPT_MAX_TOTAL_CONNECTIONS);
    insint_m(d, "M_MAX_PIPELINE_LENGTH", CURLMOPT_MAX_PIPELINE_LENGTH);
    insint_m(d, "M_CONTENT_LENGTH_PENALTY_SIZE", CURLMOPT_CONTENT_LENGTH_PENALTY_SIZE);
    insint_m(d, "M_CHUNK_LENGTH_PENALTY_SIZE", CURLMOPT_CHUNK_LENGTH_PENALTY_SIZE);
    insint_m(d, "M_PIPELINING_SITE_BL", CURLMOPT_PIPELINING_SITE_BL);
    insint_m(d, "M_PIPELINING_SERVER_BL", CURLMOPT_PIPELINING_SERVER_BL);
#endif

#if LIBCURL_VERSION_NUM >= MAKE_LIBCURL_VERSION(7, 43, 0)
    insint_m(d, "PIPE_NOTHING", CURLPIPE_NOTHING);
    insint_m(d, "PIPE_HTTP1", CURLPIPE_HTTP1);
    insint_m(d, "PIPE_MULTIPLEX", CURLPIPE_MULTIPLEX);
#endif

    /* constants for setopt(IPRESOLVE, x) */
    insint_c(d, "IPRESOLVE_WHATEVER", CURL_IPRESOLVE_WHATEVER);
    insint_c(d, "IPRESOLVE_V4", CURL_IPRESOLVE_V4);
    insint_c(d, "IPRESOLVE_V6", CURL_IPRESOLVE_V6);

    /* constants for setopt(HTTP_VERSION, x) */
    insint_c(d, "CURL_HTTP_VERSION_NONE", CURL_HTTP_VERSION_NONE);
    insint_c(d, "CURL_HTTP_VERSION_1_0", CURL_HTTP_VERSION_1_0);
    insint_c(d, "CURL_HTTP_VERSION_1_1", CURL_HTTP_VERSION_1_1);
#if LIBCURL_VERSION_NUM >= MAKE_LIBCURL_VERSION(7, 33, 0)
    insint_c(d, "CURL_HTTP_VERSION_2_0", CURL_HTTP_VERSION_2_0);
#endif
#if LIBCURL_VERSION_NUM >= MAKE_LIBCURL_VERSION(7, 43, 0)
    insint_c(d, "CURL_HTTP_VERSION_2", CURL_HTTP_VERSION_2);
#endif
#if LIBCURL_VERSION_NUM >= MAKE_LIBCURL_VERSION(7, 47, 0)
    insint_c(d, "CURL_HTTP_VERSION_2TLS", CURL_HTTP_VERSION_2TLS);
#endif
#if LIBCURL_VERSION_NUM >= MAKE_LIBCURL_VERSION(7, 49, 0)
    insint_c(d, "CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE", CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE);
    insint_c(d, "TCP_FASTOPEN", CURLOPT_TCP_FASTOPEN);
#endif
    insint_c(d, "CURL_HTTP_VERSION_LAST", CURL_HTTP_VERSION_LAST);

    /* CURL_NETRC_OPTION: constants for setopt(NETRC, x) */
    insint_c(d, "NETRC_OPTIONAL", CURL_NETRC_OPTIONAL);
    insint_c(d, "NETRC_IGNORED", CURL_NETRC_IGNORED);
    insint_c(d, "NETRC_REQUIRED", CURL_NETRC_REQUIRED);

    /* constants for setopt(SSLVERSION, x) */
    insint_c(d, "SSLVERSION_DEFAULT", CURL_SSLVERSION_DEFAULT);
    insint_c(d, "SSLVERSION_SSLv2", CURL_SSLVERSION_SSLv2);
    insint_c(d, "SSLVERSION_SSLv3", CURL_SSLVERSION_SSLv3);
    insint_c(d, "SSLVERSION_TLSv1", CURL_SSLVERSION_TLSv1);
#if LIBCURL_VERSION_NUM >= MAKE_LIBCURL_VERSION(7, 34, 0)
    insint_c(d, "SSLVERSION_TLSv1_0", CURL_SSLVERSION_TLSv1_0);
    insint_c(d, "SSLVERSION_TLSv1_1", CURL_SSLVERSION_TLSv1_1);
    insint_c(d, "SSLVERSION_TLSv1_2", CURL_SSLVERSION_TLSv1_2);
#endif
#if LIBCURL_VERSION_NUM >= MAKE_LIBCURL_VERSION(7, 52, 0)
    insint_c(d, "SSLVERSION_TLSv1_3", CURL_SSLVERSION_TLSv1_3);
#endif
#if LIBCURL_VERSION_NUM >= MAKE_LIBCURL_VERSION(7, 54, 0)
    insint_c(d, "SSLVERSION_MAX_DEFAULT", CURL_SSLVERSION_MAX_DEFAULT);
    insint_c(d, "SSLVERSION_MAX_TLSv1_0", CURL_SSLVERSION_MAX_TLSv1_0);
    insint_c(d, "SSLVERSION_MAX_TLSv1_1", CURL_SSLVERSION_MAX_TLSv1_1);
    insint_c(d, "SSLVERSION_MAX_TLSv1_2", CURL_SSLVERSION_MAX_TLSv1_2);
    insint_c(d, "SSLVERSION_MAX_TLSv1_3", CURL_SSLVERSION_MAX_TLSv1_3);
#endif

    /* curl_TimeCond: constants for setopt(TIMECONDITION, x) */
    insint_c(d, "TIMECONDITION_NONE", CURL_TIMECOND_NONE);
    insint_c(d, "TIMECONDITION_IFMODSINCE", CURL_TIMECOND_IFMODSINCE);
    insint_c(d, "TIMECONDITION_IFUNMODSINCE", CURL_TIMECOND_IFUNMODSINCE);
    insint_c(d, "TIMECONDITION_LASTMOD", CURL_TIMECOND_LASTMOD);

    /* constants for setopt(CURLOPT_SSH_AUTH_TYPES, x) */
    insint_c(d, "SSH_AUTH_ANY", CURLSSH_AUTH_ANY);
    insint_c(d, "SSH_AUTH_NONE", CURLSSH_AUTH_NONE);
    insint_c(d, "SSH_AUTH_PUBLICKEY", CURLSSH_AUTH_PUBLICKEY);
    insint_c(d, "SSH_AUTH_PASSWORD", CURLSSH_AUTH_PASSWORD);
    insint_c(d, "SSH_AUTH_HOST", CURLSSH_AUTH_HOST);
    insint_c(d, "SSH_AUTH_KEYBOARD", CURLSSH_AUTH_KEYBOARD);
    insint_c(d, "SSH_AUTH_DEFAULT", CURLSSH_AUTH_DEFAULT);
#if LIBCURL_VERSION_NUM >= MAKE_LIBCURL_VERSION(7, 28, 0)
    insint_c(d, "SSH_AUTH_AGENT", CURLSSH_AUTH_AGENT);
#endif

#if LIBCURL_VERSION_NUM >= MAKE_LIBCURL_VERSION(7, 37, 0)
    insint_c(d, "HEADER_UNIFIED", CURLHEADER_UNIFIED);
    insint_c(d, "HEADER_SEPARATE", CURLHEADER_SEPARATE);
#endif

#if LIBCURL_VERSION_NUM >= MAKE_LIBCURL_VERSION(7, 21, 5)
    insint_c(d, "SOCKOPT_ALREADY_CONNECTED", CURL_SOCKOPT_ALREADY_CONNECTED);
    insint_c(d, "SOCKOPT_ERROR", CURL_SOCKOPT_ERROR);
    insint_c(d, "SOCKOPT_OK", CURL_SOCKOPT_OK);
#endif

#ifdef HAVE_CURL_7_19_6_OPTS
    /* curl_khtype constants */
    insint_c(d, "KHTYPE_UNKNOWN", CURLKHTYPE_UNKNOWN);
    insint_c(d, "KHTYPE_RSA1", CURLKHTYPE_RSA1);
    insint_c(d, "KHTYPE_RSA", CURLKHTYPE_RSA);
    insint_c(d, "KHTYPE_DSS", CURLKHTYPE_DSS);

    /* curl_khmatch constants, passed to sshkeycallback */
    insint_c(d, "KHMATCH_OK", CURLKHMATCH_OK);
    insint_c(d, "KHMATCH_MISMATCH", CURLKHMATCH_MISMATCH);
    insint_c(d, "KHMATCH_MISSING", CURLKHMATCH_MISSING);

    /* return values for CURLOPT_SSH_KEYFUNCTION */
    insint_c(d, "KHSTAT_FINE_ADD_TO_FILE", CURLKHSTAT_FINE_ADD_TO_FILE);
    insint_c(d, "KHSTAT_FINE", CURLKHSTAT_FINE);
    insint_c(d, "KHSTAT_REJECT", CURLKHSTAT_REJECT);
    insint_c(d, "KHSTAT_DEFER", CURLKHSTAT_DEFER);
#endif

#if LIBCURL_VERSION_NUM >= MAKE_LIBCURL_VERSION(7, 28, 0)
    insint_c(d, "SOCKTYPE_ACCEPT", CURLSOCKTYPE_ACCEPT);
#endif
    insint_c(d, "SOCKTYPE_IPCXN", CURLSOCKTYPE_IPCXN);

    insint_c(d, "USESSL_NONE", CURLUSESSL_NONE);
    insint_c(d, "USESSL_TRY", CURLUSESSL_TRY);
    insint_c(d, "USESSL_CONTROL", CURLUSESSL_CONTROL);
    insint_c(d, "USESSL_ALL", CURLUSESSL_ALL);

    /* CURLINFO: symbolic constants for getinfo(x) */
    insint_c(d, "EFFECTIVE_URL", CURLINFO_EFFECTIVE_URL);
    /* same as CURLINFO_RESPONSE_CODE */
    insint_c(d, "HTTP_CODE", CURLINFO_HTTP_CODE);
    insint_c(d, "RESPONSE_CODE", CURLINFO_RESPONSE_CODE);
    insint_c(d, "TOTAL_TIME", CURLINFO_TOTAL_TIME);
    insint_c(d, "NAMELOOKUP_TIME", CURLINFO_NAMELOOKUP_TIME);
    insint_c(d, "CONNECT_TIME", CURLINFO_CONNECT_TIME);
    insint_c(d, "APPCONNECT_TIME", CURLINFO_APPCONNECT_TIME);
    insint_c(d, "PRETRANSFER_TIME", CURLINFO_PRETRANSFER_TIME);
    insint_c(d, "SIZE_UPLOAD", CURLINFO_SIZE_UPLOAD);
    insint_c(d, "SIZE_DOWNLOAD", CURLINFO_SIZE_DOWNLOAD);
    insint_c(d, "SPEED_DOWNLOAD", CURLINFO_SPEED_DOWNLOAD);
    insint_c(d, "SPEED_UPLOAD", CURLINFO_SPEED_UPLOAD);
    insint_c(d, "HEADER_SIZE", CURLINFO_HEADER_SIZE);
    insint_c(d, "REQUEST_SIZE", CURLINFO_REQUEST_SIZE);
    insint_c(d, "SSL_VERIFYRESULT", CURLINFO_SSL_VERIFYRESULT);
    insint_c(d, "INFO_FILETIME", CURLINFO_FILETIME);
    insint_c(d, "CONTENT_LENGTH_DOWNLOAD", CURLINFO_CONTENT_LENGTH_DOWNLOAD);
    insint_c(d, "CONTENT_LENGTH_UPLOAD", CURLINFO_CONTENT_LENGTH_UPLOAD);
    insint_c(d, "STARTTRANSFER_TIME", CURLINFO_STARTTRANSFER_TIME);
    insint_c(d, "CONTENT_TYPE", CURLINFO_CONTENT_TYPE);
    insint_c(d, "REDIRECT_TIME", CURLINFO_REDIRECT_TIME);
    insint_c(d, "REDIRECT_COUNT", CURLINFO_REDIRECT_COUNT);
    insint_c(d, "REDIRECT_URL", CURLINFO_REDIRECT_URL);
    insint_c(d, "PRIMARY_IP", CURLINFO_PRIMARY_IP);
#ifdef HAVE_CURLINFO_PRIMARY_PORT
    insint_c(d, "PRIMARY_PORT", CURLINFO_PRIMARY_PORT);
#endif
#ifdef HAVE_CURLINFO_LOCAL_IP
    insint_c(d, "LOCAL_IP", CURLINFO_LOCAL_IP);
#endif
#ifdef HAVE_CURLINFO_LOCAL_PORT
    insint_c(d, "LOCAL_PORT", CURLINFO_LOCAL_PORT);
#endif
    insint_c(d, "HTTP_CONNECTCODE", CURLINFO_HTTP_CONNECTCODE);
    insint_c(d, "HTTPAUTH_AVAIL", CURLINFO_HTTPAUTH_AVAIL);
    insint_c(d, "PROXYAUTH_AVAIL", CURLINFO_PROXYAUTH_AVAIL);
    insint_c(d, "OS_ERRNO", CURLINFO_OS_ERRNO);
    insint_c(d, "NUM_CONNECTS", CURLINFO_NUM_CONNECTS);
    insint_c(d, "SSL_ENGINES", CURLINFO_SSL_ENGINES);
    insint_c(d, "INFO_COOKIELIST", CURLINFO_COOKIELIST);
    insint_c(d, "LASTSOCKET", CURLINFO_LASTSOCKET);
    insint_c(d, "FTP_ENTRY_PATH", CURLINFO_FTP_ENTRY_PATH);
#ifdef HAVE_CURLOPT_CERTINFO
    insint_c(d, "INFO_CERTINFO", CURLINFO_CERTINFO);
#endif
#ifdef HAVE_CURL_7_19_4_OPTS
    insint_c(d, "CONDITION_UNMET", CURLINFO_CONDITION_UNMET);
#endif
#if LIBCURL_VERSION_NUM >= MAKE_LIBCURL_VERSION(7, 20, 0)
    insint_c(d, "INFO_RTSP_CLIENT_CSEQ", CURLINFO_RTSP_CLIENT_CSEQ);
    insint_c(d, "INFO_RTSP_CSEQ_RECV", CURLINFO_RTSP_CSEQ_RECV);
    insint_c(d, "INFO_RTSP_SERVER_CSEQ", CURLINFO_RTSP_SERVER_CSEQ);
    insint_c(d, "INFO_RTSP_SESSION_ID", CURLINFO_RTSP_SESSION_ID);
    insint_c(d, "RTSPREQ_NONE",CURL_RTSPREQ_NONE);
    insint_c(d, "RTSPREQ_OPTIONS",CURL_RTSPREQ_OPTIONS);
    insint_c(d, "RTSPREQ_DESCRIBE",CURL_RTSPREQ_DESCRIBE);
    insint_c(d, "RTSPREQ_ANNOUNCE",CURL_RTSPREQ_ANNOUNCE);
    insint_c(d, "RTSPREQ_SETUP",CURL_RTSPREQ_SETUP);
    insint_c(d, "RTSPREQ_PLAY",CURL_RTSPREQ_PLAY);
    insint_c(d, "RTSPREQ_PAUSE",CURL_RTSPREQ_PAUSE);
    insint_c(d, "RTSPREQ_TEARDOWN",CURL_RTSPREQ_TEARDOWN);
    insint_c(d, "RTSPREQ_GET_PARAMETER",CURL_RTSPREQ_GET_PARAMETER);
    insint_c(d, "RTSPREQ_SET_PARAMETER",CURL_RTSPREQ_SET_PARAMETER);
    insint_c(d, "RTSPREQ_RECORD",CURL_RTSPREQ_RECORD);
    insint_c(d, "RTSPREQ_RECEIVE",CURL_RTSPREQ_RECEIVE);
    insint_c(d, "RTSPREQ_LAST",CURL_RTSPREQ_LAST);
#endif

    /* CURLPAUSE: symbolic constants for pause(bitmask) */
    insint_c(d, "PAUSE_RECV", CURLPAUSE_RECV);
    insint_c(d, "PAUSE_SEND", CURLPAUSE_SEND);
    insint_c(d, "PAUSE_ALL",  CURLPAUSE_ALL);
    insint_c(d, "PAUSE_CONT", CURLPAUSE_CONT);

#ifdef HAVE_CURL_7_19_5_OPTS
    /* CURL_SEEKFUNC: return values for seek function */
    insint_c(d, "SEEKFUNC_OK", CURL_SEEKFUNC_OK);
    insint_c(d, "SEEKFUNC_FAIL", CURL_SEEKFUNC_FAIL);
    insint_c(d, "SEEKFUNC_CANTSEEK", CURL_SEEKFUNC_CANTSEEK);
#endif

#ifdef HAVE_CURLOPT_DNS_SERVERS
    insint_c(d, "DNS_SERVERS", CURLOPT_DNS_SERVERS);
#endif

#ifdef HAVE_CURLOPT_POSTREDIR
    insint_c(d, "REDIR_POST_301", CURL_REDIR_POST_301);
    insint_c(d, "REDIR_POST_302", CURL_REDIR_POST_302);
# ifdef HAVE_CURL_REDIR_POST_303
    insint_c(d, "REDIR_POST_303", CURL_REDIR_POST_303);
# endif
    insint_c(d, "REDIR_POST_ALL", CURL_REDIR_POST_ALL);
#endif

#ifdef HAVE_CURLOPT_CONNECT_TO
    insint_c(d, "CONNECT_TO", CURLOPT_CONNECT_TO);
#endif

#ifdef HAVE_CURLINFO_HTTP_VERSION
    insint_c(d, "INFO_HTTP_VERSION", CURLINFO_HTTP_VERSION);
#endif

    /* options for global_init() */
    insint(d, "GLOBAL_SSL", CURL_GLOBAL_SSL);
    insint(d, "GLOBAL_WIN32", CURL_GLOBAL_WIN32);
    insint(d, "GLOBAL_ALL", CURL_GLOBAL_ALL);
    insint(d, "GLOBAL_NOTHING", CURL_GLOBAL_NOTHING);
    insint(d, "GLOBAL_DEFAULT", CURL_GLOBAL_DEFAULT);
#ifdef CURL_GLOBAL_ACK_EINTR
    /* CURL_GLOBAL_ACK_EINTR was introduced in libcurl-7.30.0 */
    insint(d, "GLOBAL_ACK_EINTR", CURL_GLOBAL_ACK_EINTR);
#endif


    /* constants for curl_multi_socket interface */
    insint(d, "CSELECT_IN", CURL_CSELECT_IN);
    insint(d, "CSELECT_OUT", CURL_CSELECT_OUT);
    insint(d, "CSELECT_ERR", CURL_CSELECT_ERR);
    insint(d, "SOCKET_TIMEOUT", CURL_SOCKET_TIMEOUT);
    insint(d, "POLL_NONE", CURL_POLL_NONE);
    insint(d, "POLL_IN", CURL_POLL_IN);
    insint(d, "POLL_OUT", CURL_POLL_OUT);
    insint(d, "POLL_INOUT", CURL_POLL_INOUT);
    insint(d, "POLL_REMOVE", CURL_POLL_REMOVE);

    /* curl_lock_data: XXX do we need this in pycurl ??? */
    /* curl_lock_access: XXX do we need this in pycurl ??? */
    /* CURLSHcode: XXX do we need this in pycurl ??? */
    /* CURLSHoption: XXX do we need this in pycurl ??? */

    /* CURLversion: constants for curl_version_info(x) */
#if 0
    /* XXX - do we need these ?? */
    insint(d, "VERSION_FIRST", CURLVERSION_FIRST);
    insint(d, "VERSION_SECOND", CURLVERSION_SECOND);
    insint(d, "VERSION_THIRD", CURLVERSION_THIRD);
    insint(d, "VERSION_NOW", CURLVERSION_NOW);
#endif

    /* version features - bitmasks for curl_version_info_data.features */
    insint(d, "VERSION_IPV6", CURL_VERSION_IPV6);
    insint(d, "VERSION_KERBEROS4", CURL_VERSION_KERBEROS4);
#if LIBCURL_VERSION_NUM >= MAKE_LIBCURL_VERSION(7, 40, 0)
    insint(d, "VERSION_KERBEROS5", CURL_VERSION_KERBEROS5);
#endif
    insint(d, "VERSION_SSL", CURL_VERSION_SSL);
    insint(d, "VERSION_LIBZ", CURL_VERSION_LIBZ);
    insint(d, "VERSION_NTLM", CURL_VERSION_NTLM);
    insint(d, "VERSION_GSSNEGOTIATE", CURL_VERSION_GSSNEGOTIATE);
    insint(d, "VERSION_DEBUG", CURL_VERSION_DEBUG);
#if LIBCURL_VERSION_NUM >= MAKE_LIBCURL_VERSION(7, 19, 6)
    insint(d, "VERSION_CURLDEBUG", CURL_VERSION_CURLDEBUG);
#endif
    insint(d, "VERSION_ASYNCHDNS", CURL_VERSION_ASYNCHDNS);
    insint(d, "VERSION_SPNEGO", CURL_VERSION_SPNEGO);
    insint(d, "VERSION_LARGEFILE", CURL_VERSION_LARGEFILE);
    insint(d, "VERSION_IDN", CURL_VERSION_IDN);
    insint(d, "VERSION_SSPI", CURL_VERSION_SSPI);
#if LIBCURL_VERSION_NUM >= MAKE_LIBCURL_VERSION(7, 38, 0)
    insint(d, "VERSION_GSSAPI", CURL_VERSION_GSSAPI);
#endif
    insint(d, "VERSION_CONV", CURL_VERSION_CONV);
#if LIBCURL_VERSION_NUM >= MAKE_LIBCURL_VERSION(7, 21, 4)
    insint(d, "VERSION_TLSAUTH_SRP", CURL_VERSION_TLSAUTH_SRP);
#endif
#if LIBCURL_VERSION_NUM >= MAKE_LIBCURL_VERSION(7, 22, 0)
    insint(d, "VERSION_NTLM_WB", CURL_VERSION_NTLM_WB);
#endif
#if LIBCURL_VERSION_NUM >= MAKE_LIBCURL_VERSION(7, 33, 0)
    insint(d, "VERSION_HTTP2", CURL_VERSION_HTTP2);
#endif
#if LIBCURL_VERSION_NUM >= MAKE_LIBCURL_VERSION(7, 40, 0)
    insint(d, "VERSION_UNIX_SOCKETS", CURL_VERSION_UNIX_SOCKETS);
#endif
#if LIBCURL_VERSION_NUM >= MAKE_LIBCURL_VERSION(7, 47, 0)
    insint(d, "VERSION_PSL", CURL_VERSION_PSL);
#endif

    /**
     ** the order of these constants mostly follows <curl/multi.h>
     **/

    /* CURLMcode: multi error codes */
    /* old symbol */
    insint_m(d, "E_CALL_MULTI_PERFORM", CURLM_CALL_MULTI_PERFORM);
    /* new symbol for consistency */
    insint_m(d, "E_MULTI_CALL_MULTI_PERFORM", CURLM_CALL_MULTI_PERFORM);
    insint_m(d, "E_MULTI_OK", CURLM_OK);
    insint_m(d, "E_MULTI_BAD_HANDLE", CURLM_BAD_HANDLE);
    insint_m(d, "E_MULTI_BAD_EASY_HANDLE", CURLM_BAD_EASY_HANDLE);
    insint_m(d, "E_MULTI_BAD_SOCKET", CURLM_BAD_SOCKET);
    insint_m(d, "E_MULTI_CALL_MULTI_SOCKET", CURLM_CALL_MULTI_SOCKET);
    insint_m(d, "E_MULTI_OUT_OF_MEMORY", CURLM_OUT_OF_MEMORY);
    insint_m(d, "E_MULTI_INTERNAL_ERROR", CURLM_INTERNAL_ERROR);
    insint_m(d, "E_MULTI_UNKNOWN_OPTION", CURLM_UNKNOWN_OPTION);
#if LIBCURL_VERSION_NUM >= MAKE_LIBCURL_VERSION(7, 32, 1)
    insint_m(d, "E_MULTI_ADDED_ALREADY", CURLM_ADDED_ALREADY);
#endif
    /* curl shared constants */
    insint_s(d, "SH_SHARE", CURLSHOPT_SHARE);
    insint_s(d, "SH_UNSHARE", CURLSHOPT_UNSHARE);

    insint_s(d, "LOCK_DATA_COOKIE", CURL_LOCK_DATA_COOKIE);
    insint_s(d, "LOCK_DATA_DNS", CURL_LOCK_DATA_DNS);
    insint_s(d, "LOCK_DATA_SSL_SESSION", CURL_LOCK_DATA_SSL_SESSION);

    /* Initialize callback locks if ssl is enabled */
#if defined(PYCURL_NEED_SSL_TSL)
    if (pycurl_ssl_init() != 0) {
        goto error;
    }
#endif

#if PY_MAJOR_VERSION >= 3
    xio_module = PyImport_ImportModule("io");
    if (xio_module == NULL) {
        goto error;
    }
    bytesio = PyObject_GetAttrString(xio_module, "BytesIO");
    if (bytesio == NULL) {
        goto error;
    }
    stringio = PyObject_GetAttrString(xio_module, "StringIO");
    if (stringio == NULL) {
        goto error;
    }
#else
    xio_module = PyImport_ImportModule("cStringIO");
    if (xio_module == NULL) {
        PyErr_Clear();
        xio_module = PyImport_ImportModule("StringIO");
        if (xio_module == NULL) {
            goto error;
        }
    }
    stringio = PyObject_GetAttrString(xio_module, "StringIO");
    if (stringio == NULL) {
        goto error;
    }
    bytesio = stringio;
    Py_INCREF(bytesio);
#endif

    collections_module = PyImport_ImportModule("collections");
    if (collections_module == NULL) {
        goto error;
    }
    named_tuple = PyObject_GetAttrString(collections_module, "namedtuple");
    if (named_tuple == NULL) {
        goto error;
    }
#ifdef HAVE_CURL_7_19_6_OPTS
    arglist = Py_BuildValue("ss", "KhKey", "key keytype");
    if (arglist == NULL) {
        goto error;
    }
    khkey_type = PyObject_Call(named_tuple, arglist, NULL);
    if (khkey_type == NULL) {
        goto error;
    }
    Py_DECREF(arglist);
    PyDict_SetItemString(d, "KhKey", khkey_type);
#endif

    arglist = Py_BuildValue("ss", "CurlSockAddr", "family socktype protocol addr");
    if (arglist == NULL) {
        goto error;
    }
    curl_sockaddr_type = PyObject_Call(named_tuple, arglist, NULL);
    if (curl_sockaddr_type == NULL) {
        goto error;
    }
    Py_DECREF(arglist);
    PyDict_SetItemString(d, "CurlSockAddr", curl_sockaddr_type);

#ifdef WITH_THREAD
    /* Finally initialize global interpreter lock */
    PyEval_InitThreads();
#endif

#if PY_MAJOR_VERSION >= 3
    return m;
#else
    PYCURL_MODINIT_RETURN_NULL;
#endif

error:
    Py_XDECREF(curlobject_constants);
    Py_XDECREF(curlmultiobject_constants);
    Py_XDECREF(curlshareobject_constants);
    Py_XDECREF(ErrorObject);
    Py_XDECREF(collections_module);
    Py_XDECREF(named_tuple);
    Py_XDECREF(xio_module);
    Py_XDECREF(bytesio);
    Py_XDECREF(stringio);
    Py_XDECREF(arglist);
#ifdef HAVE_CURL_7_19_6_OPTS
    Py_XDECREF(khkey_type);
    Py_XDECREF(curl_sockaddr_type);
#endif
    PyMem_Free(g_pycurl_useragent);
    if (!PyErr_Occurred())
        PyErr_SetString(PyExc_ImportError, "curl module init failed");
    PYCURL_MODINIT_RETURN_NULL;
}



/*************************************************************************
// static utility functions
**************************************************************************/


/* assert some CurlMultiObject invariants */
static void
assert_multi_state(const CurlMultiObject *self)
{
    assert(self != NULL);
    assert(Py_TYPE(self) == p_CurlMulti_Type);
#ifdef WITH_THREAD
    if (self->state != NULL) {
        assert(self->multi_handle != NULL);
    }
#endif
}


static int
check_multi_state(const CurlMultiObject *self, int flags, const char *name)
{
    assert_multi_state(self);
    if ((flags & 1) && self->multi_handle == NULL) {
        PyErr_Format(ErrorObject, "cannot invoke %s() - no multi handle", name);
        return -1;
    }
#ifdef WITH_THREAD
    if ((flags & 2) && self->state != NULL) {
        PyErr_Format(ErrorObject, "cannot invoke %s() - multi_perform() is currently running", name);
        return -1;
    }
#endif
    return 0;
}


/*************************************************************************
// CurlMultiObject
**************************************************************************/

/* --------------- construct/destruct (i.e. open/close) --------------- */

/* constructor */
PYCURL_INTERNAL CurlMultiObject *
do_multi_new(PyTypeObject *subtype, PyObject *args, PyObject *kwds)
{
    CurlMultiObject *self;
    int *ptr;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "", empty_keywords)) {
        return NULL;
    }

    /* Allocate python curl-multi object */
    self = (CurlMultiObject *) p_CurlMulti_Type->tp_alloc(p_CurlMulti_Type, 0);
    if (!self) {
        return NULL;
    }

    /* tp_alloc is expected to return zeroed memory */
    for (ptr = (int *) &self->dict;
        ptr < (int *) (((char *) self) + sizeof(CurlMultiObject));
        ++ptr)
            assert(*ptr == 0);

    self->easy_object_dict = PyDict_New();
    if (self->easy_object_dict == NULL) {
        Py_DECREF(self);
        return NULL;
    }
    
    /* Allocate libcurl multi handle */
    self->multi_handle = curl_multi_init();
    if (self->multi_handle == NULL) {
        Py_DECREF(self);
        PyErr_SetString(ErrorObject, "initializing curl-multi failed");
        return NULL;
    }
    return self;
}

static void
util_multi_close(CurlMultiObject *self)
{
    assert(self != NULL);

#ifdef WITH_THREAD
    self->state = NULL;
#endif
    
    if (self->multi_handle != NULL) {
        CURLM *multi_handle = self->multi_handle;
        self->multi_handle = NULL;
        curl_multi_cleanup(multi_handle);
    }
}


static void
util_multi_xdecref(CurlMultiObject *self)
{
    Py_CLEAR(self->easy_object_dict);
    Py_CLEAR(self->dict);
    Py_CLEAR(self->t_cb);
    Py_CLEAR(self->s_cb);
}


PYCURL_INTERNAL void
do_multi_dealloc(CurlMultiObject *self)
{
    PyObject_GC_UnTrack(self);
    Py_TRASHCAN_SAFE_BEGIN(self);

    util_multi_xdecref(self);
    util_multi_close(self);

    if (self->weakreflist != NULL) {
        PyObject_ClearWeakRefs((PyObject *) self);
    }

    CurlMulti_Type.tp_free(self);
    Py_TRASHCAN_SAFE_END(self);
}


static PyObject *
do_multi_close(CurlMultiObject *self)
{
    if (check_multi_state(self, 2, "close") != 0) {
        return NULL;
    }
    util_multi_close(self);
    Py_RETURN_NONE;
}


/* --------------- GC support --------------- */

/* Drop references that may have created reference cycles. */
PYCURL_INTERNAL int
do_multi_clear(CurlMultiObject *self)
{
    util_multi_xdecref(self);
    return 0;
}

PYCURL_INTERNAL int
do_multi_traverse(CurlMultiObject *self, visitproc visit, void *arg)
{
    int err;
#undef VISIT
#define VISIT(v)    if ((v) != NULL && ((err = visit(v, arg)) != 0)) return err

    VISIT(self->dict);
    VISIT(self->easy_object_dict);

    return 0;
#undef VISIT
}


/* --------------- setopt --------------- */

static int
multi_socket_callback(CURL *easy,
                      curl_socket_t s,
                      int what,
                      void *userp,
                      void *socketp)
{
    CurlMultiObject *self;
    PyObject *arglist;
    PyObject *result = NULL;
    PYCURL_DECLARE_THREAD_STATE;

    /* acquire thread */
    self = (CurlMultiObject *)userp;
    if (!PYCURL_ACQUIRE_THREAD_MULTI())
        return 0;

    /* check args */
    if (self->s_cb == NULL)
        goto silent_error;

    if (socketp == NULL) {
        Py_INCREF(Py_None);
        socketp = Py_None;
    }

    /* run callback */
    arglist = Py_BuildValue("(iiOO)", what, s, userp, (PyObject *)socketp);
    if (arglist == NULL)
        goto verbose_error;
    result = PyEval_CallObject(self->s_cb, arglist);
    Py_DECREF(arglist);
    if (result == NULL)
        goto verbose_error;

    /* return values from socket callbacks should be ignored */

silent_error:
    Py_XDECREF(result);
    PYCURL_RELEASE_THREAD();
    return 0;
verbose_error:
    PyErr_Print();
    goto silent_error;
    return 0;
}


static int
multi_timer_callback(CURLM *multi,
                     long timeout_ms,
                     void *userp)
{
    CurlMultiObject *self;
    PyObject *arglist;
    PyObject *result = NULL;
    int ret = 0;       /* always success */
    PYCURL_DECLARE_THREAD_STATE;

    UNUSED(multi);

    /* acquire thread */
    self = (CurlMultiObject *)userp;
    if (!PYCURL_ACQUIRE_THREAD_MULTI())
        return ret;

    /* check args */
    if (self->t_cb == NULL)
        goto silent_error;

    /* run callback */
    arglist = Py_BuildValue("(i)", timeout_ms);
    if (arglist == NULL)
        goto verbose_error;
    result = PyEval_CallObject(self->t_cb, arglist);
    Py_DECREF(arglist);
    if (result == NULL)
        goto verbose_error;

    /* return values from timer callbacks should be ignored */

silent_error:
    Py_XDECREF(result);
    PYCURL_RELEASE_THREAD();
    return ret;
verbose_error:
    PyErr_Print();
    goto silent_error;

    return 0;
}


static PyObject *
do_multi_setopt_int(CurlMultiObject *self, int option, PyObject *obj)
{
    long d = PyInt_AsLong(obj);
    switch(option) {
    case CURLMOPT_MAXCONNECTS:
    case CURLMOPT_PIPELINING:
#ifdef HAVE_CURL_7_30_0_PIPELINE_OPTS
    case CURLMOPT_MAX_HOST_CONNECTIONS:
    case CURLMOPT_MAX_TOTAL_CONNECTIONS:
    case CURLMOPT_MAX_PIPELINE_LENGTH:
    case CURLMOPT_CONTENT_LENGTH_PENALTY_SIZE:
    case CURLMOPT_CHUNK_LENGTH_PENALTY_SIZE:
#endif
        curl_multi_setopt(self->multi_handle, option, d);
        break;
    default:
        PyErr_SetString(PyExc_TypeError, "integers are not supported for this option");
        return NULL;
    }
    Py_RETURN_NONE;
}


static PyObject *
do_multi_setopt_charpp(CurlMultiObject *self, int option, int which, PyObject *obj)
{
    Py_ssize_t len, i;
    int res;
    static const char *empty_list[] = { NULL };
    char **list = NULL;
    PyObject **encoded_objs = NULL;
    PyObject *encoded_obj = NULL;
    char *encoded_str;
    PyObject *rv = NULL;

    len = PyListOrTuple_Size(obj, which);
    if (len == 0) {
        res = curl_multi_setopt(self->multi_handle, option, empty_list);
        if (res != CURLE_OK) {
            CURLERROR_RETVAL_MULTI_DONE();
        }
        Py_RETURN_NONE;
    }

    /* add NULL terminator as the last list item */
    list = PyMem_New(char *, len+1);
    if (list == NULL) {
        PyErr_NoMemory();
        return NULL;
    }
    /* no need for the NULL terminator here */
    encoded_objs = PyMem_New(PyObject *, len);
    if (encoded_objs == NULL) {
        PyErr_NoMemory();
        goto done;
    }
    memset(encoded_objs, 0, sizeof(PyObject *) * len);

    for (i = 0; i < len; i++) {
        PyObject *listitem = PyListOrTuple_GetItem(obj, i, which);
        if (!PyText_Check(listitem)) {
            PyErr_SetString(ErrorObject, "list/tuple items must be strings");
            goto done;
        }
        encoded_str = PyText_AsString_NoNUL(listitem, &encoded_obj);
        if (encoded_str == NULL) {
            goto done;
        }
        list[i] = encoded_str;
        encoded_objs[i] = encoded_obj;
    }
    list[len] = NULL;

    res = curl_multi_setopt(self->multi_handle, option, list);
    if (res != CURLE_OK) {
        rv = NULL;
        CURLERROR_RETVAL_MULTI_DONE();
    }

    rv = Py_None;
done:
    if (encoded_objs) {
        for (i = 0; i < len; i++) {
            Py_XDECREF(encoded_objs[i]);
        }
        PyMem_Free(encoded_objs);
    }
    PyMem_Free(list);
    return rv;
}


static PyObject *
do_multi_setopt_list(CurlMultiObject *self, int option, int which, PyObject *obj)
{
    switch(option) {
#ifdef HAVE_CURL_7_30_0_PIPELINE_OPTS
    case CURLMOPT_PIPELINING_SITE_BL:
    case CURLMOPT_PIPELINING_SERVER_BL:
#endif
        return do_multi_setopt_charpp(self, option, which, obj);
        break;
    default:
        PyErr_SetString(PyExc_TypeError, "lists/tuples are not supported for this option");
        return NULL;
    }
    Py_RETURN_NONE;
}


static PyObject *
do_multi_setopt_callable(CurlMultiObject *self, int option, PyObject *obj)
{
    /* We use function types here to make sure that our callback
     * definitions exactly match the <curl/multi.h> interface.
     */
    const curl_multi_timer_callback t_cb = multi_timer_callback;
    const curl_socket_callback s_cb = multi_socket_callback;

    switch(option) {
    case CURLMOPT_SOCKETFUNCTION:
        curl_multi_setopt(self->multi_handle, CURLMOPT_SOCKETFUNCTION, s_cb);
        curl_multi_setopt(self->multi_handle, CURLMOPT_SOCKETDATA, self);
        Py_INCREF(obj);
        self->s_cb = obj;
        break;
    case CURLMOPT_TIMERFUNCTION:
        curl_multi_setopt(self->multi_handle, CURLMOPT_TIMERFUNCTION, t_cb);
        curl_multi_setopt(self->multi_handle, CURLMOPT_TIMERDATA, self);
        Py_INCREF(obj);
        self->t_cb = obj;
        break;
    default:
        PyErr_SetString(PyExc_TypeError, "callables are not supported for this option");
        return NULL;
    }
    Py_RETURN_NONE;
}


static PyObject *
do_multi_setopt(CurlMultiObject *self, PyObject *args)
{
    int option, which;
    PyObject *obj;

    if (!PyArg_ParseTuple(args, "iO:setopt", &option, &obj))
        return NULL;
    if (check_multi_state(self, 1 | 2, "setopt") != 0)
        return NULL;

    /* Early checks of option value */
    if (option <= 0)
        goto error;
    if (option >= (int)CURLOPTTYPE_OFF_T + MOPTIONS_SIZE)
        goto error;
    if (option % 10000 >= MOPTIONS_SIZE)
        goto error;

    /* Handle the case of integer arguments */
    if (PyInt_Check(obj)) {
        return do_multi_setopt_int(self, option, obj);
    }

    /* Handle the case of list or tuple objects */
    which = PyListOrTuple_Check(obj);
    if (which) {
        return do_multi_setopt_list(self, option, which, obj);
    }

    if (PyFunction_Check(obj) || PyCFunction_Check(obj) ||
        PyCallable_Check(obj) || PyMethod_Check(obj)) {
        return do_multi_setopt_callable(self, option, obj);
    }

    /* Failed to match any of the function signatures -- return error */
error:
    PyErr_SetString(PyExc_TypeError, "invalid arguments to setopt");
    return NULL;
}


/* --------------- timeout --------------- */

static PyObject *
do_multi_timeout(CurlMultiObject *self)
{
    CURLMcode res;
    long timeout;

    if (check_multi_state(self, 1 | 2, "timeout") != 0) {
        return NULL;
    }

    res = curl_multi_timeout(self->multi_handle, &timeout);
    if (res != CURLM_OK) {
        CURLERROR_MSG("timeout failed");
    }

    /* Return number of millisecs until timeout */
    return Py_BuildValue("l", timeout);
}


/* --------------- assign --------------- */

static PyObject *
do_multi_assign(CurlMultiObject *self, PyObject *args)
{
    CURLMcode res;
    curl_socket_t socket;
    PyObject *obj;

    if (!PyArg_ParseTuple(args, "iO:assign", &socket, &obj))
        return NULL;
    if (check_multi_state(self, 1 | 2, "assign") != 0) {
        return NULL;
    }
    Py_INCREF(obj);

    res = curl_multi_assign(self->multi_handle, socket, obj);
    if (res != CURLM_OK) {
        CURLERROR_MSG("assign failed");
    }

    Py_RETURN_NONE;
}


/* --------------- socket_action --------------- */
static PyObject *
do_multi_socket_action(CurlMultiObject *self, PyObject *args)
{
    CURLMcode res;
    curl_socket_t socket;
    int ev_bitmask;
    int running = -1;

    if (!PyArg_ParseTuple(args, "ii:socket_action", &socket, &ev_bitmask))
        return NULL;
    if (check_multi_state(self, 1 | 2, "socket_action") != 0) {
        return NULL;
    }

    PYCURL_BEGIN_ALLOW_THREADS
    res = curl_multi_socket_action(self->multi_handle, socket, ev_bitmask, &running);
    PYCURL_END_ALLOW_THREADS

    if (res != CURLM_OK) {
        CURLERROR_MSG("multi_socket_action failed");
    }
    /* Return a tuple with the result and the number of running handles */
    return Py_BuildValue("(ii)", (int)res, running);
}

/* --------------- socket_all --------------- */

static PyObject *
do_multi_socket_all(CurlMultiObject *self)
{
    CURLMcode res;
    int running = -1;

    if (check_multi_state(self, 1 | 2, "socket_all") != 0) {
        return NULL;
    }

    PYCURL_BEGIN_ALLOW_THREADS
    res = curl_multi_socket_all(self->multi_handle, &running);
    PYCURL_END_ALLOW_THREADS

    /* We assume these errors are ok, otherwise raise exception */
    if (res != CURLM_OK && res != CURLM_CALL_MULTI_PERFORM) {
        CURLERROR_MSG("perform failed");
    }

    /* Return a tuple with the result and the number of running handles */
    return Py_BuildValue("(ii)", (int)res, running);
}


/* --------------- perform --------------- */

static PyObject *
do_multi_perform(CurlMultiObject *self)
{
    CURLMcode res;
    int running = -1;

    if (check_multi_state(self, 1 | 2, "perform") != 0) {
        return NULL;
    }

    PYCURL_BEGIN_ALLOW_THREADS
    res = curl_multi_perform(self->multi_handle, &running);
    PYCURL_END_ALLOW_THREADS

    /* We assume these errors are ok, otherwise raise exception */
    if (res != CURLM_OK && res != CURLM_CALL_MULTI_PERFORM) {
        CURLERROR_MSG("perform failed");
    }

    /* Return a tuple with the result and the number of running handles */
    return Py_BuildValue("(ii)", (int)res, running);
}


/* --------------- add_handle/remove_handle --------------- */

/* static utility function */
static int
check_multi_add_remove(const CurlMultiObject *self, const CurlObject *obj)
{
    /* check CurlMultiObject status */
    assert_multi_state(self);
    if (self->multi_handle == NULL) {
        PyErr_SetString(ErrorObject, "cannot add/remove handle - multi-stack is closed");
        return -1;
    }
#ifdef WITH_THREAD
    if (self->state != NULL) {
        PyErr_SetString(ErrorObject, "cannot add/remove handle - multi_perform() already running");
        return -1;
    }
#endif
    /* check CurlObject status */
    assert_curl_state(obj);
#ifdef WITH_THREAD
    if (obj->state != NULL) {
        PyErr_SetString(ErrorObject, "cannot add/remove handle - perform() of curl object already running");
        return -1;
    }
#endif
    if (obj->multi_stack != NULL && obj->multi_stack != self) {
        PyErr_SetString(ErrorObject, "cannot add/remove handle - curl object already on another multi-stack");
        return -1;
    }
    return 0;
}


static PyObject *
do_multi_add_handle(CurlMultiObject *self, PyObject *args)
{
    CurlObject *obj;
    CURLMcode res;

    if (!PyArg_ParseTuple(args, "O!:add_handle", p_Curl_Type, &obj)) {
        return NULL;
    }
    if (check_multi_add_remove(self, obj) != 0) {
        return NULL;
    }
    if (obj->handle == NULL) {
        PyErr_SetString(ErrorObject, "curl object already closed");
        return NULL;
    }
    if (obj->multi_stack == self) {
        PyErr_SetString(ErrorObject, "curl object already on this multi-stack");
        return NULL;
    }
    
    PyDict_SetItem(self->easy_object_dict, (PyObject *) obj, Py_True);
    
    assert(obj->multi_stack == NULL);
    res = curl_multi_add_handle(self->multi_handle, obj->handle);
    if (res != CURLM_OK) {
        PyDict_DelItem(self->easy_object_dict, (PyObject *) obj);
        CURLERROR_MSG("curl_multi_add_handle() failed due to internal errors");
    }
    obj->multi_stack = self;
    Py_INCREF(self);
    
    Py_RETURN_NONE;
}


static PyObject *
do_multi_remove_handle(CurlMultiObject *self, PyObject *args)
{
    CurlObject *obj;
    CURLMcode res;

    if (!PyArg_ParseTuple(args, "O!:remove_handle", p_Curl_Type, &obj)) {
        return NULL;
    }
    if (check_multi_add_remove(self, obj) != 0) {
        return NULL;
    }
    if (obj->handle == NULL) {
        /* CurlObject handle already closed -- ignore */
        if (PyDict_GetItem(self->easy_object_dict, (PyObject *) obj)) {
            PyDict_DelItem(self->easy_object_dict, (PyObject *) obj);
        }
        goto done;
    }
    if (obj->multi_stack != self) {
        PyErr_SetString(ErrorObject, "curl object not on this multi-stack");
        return NULL;
    }
    res = curl_multi_remove_handle(self->multi_handle, obj->handle);
    if (res == CURLM_OK) {
        PyDict_DelItem(self->easy_object_dict, (PyObject *) obj);
        // if PyDict_DelItem fails, remove_handle call will also fail.
        // but the dictionary should always have our object in it
        // hence this failure shouldn't happen unless something unaccounted
        // for went wrong
    } else {
        CURLERROR_MSG("curl_multi_remove_handle() failed due to internal errors");
    }
    assert(obj->multi_stack == self);
    obj->multi_stack = NULL;
    Py_DECREF(self);
done:
    Py_RETURN_NONE;
}


/* --------------- fdset ---------------------- */

static PyObject *
do_multi_fdset(CurlMultiObject *self)
{
    CURLMcode res;
    int max_fd = -1, fd;
    PyObject *ret = NULL;
    PyObject *read_list = NULL, *write_list = NULL, *except_list = NULL;
    PyObject *py_fd = NULL;

    if (check_multi_state(self, 1 | 2, "fdset") != 0) {
        return NULL;
    }

    /* Clear file descriptor sets */
    FD_ZERO(&self->read_fd_set);
    FD_ZERO(&self->write_fd_set);
    FD_ZERO(&self->exc_fd_set);

    /* Don't bother releasing the gil as this is just a data structure operation */
    res = curl_multi_fdset(self->multi_handle, &self->read_fd_set,
                           &self->write_fd_set, &self->exc_fd_set, &max_fd);
    if (res != CURLM_OK) {
        CURLERROR_MSG("curl_multi_fdset() failed due to internal errors");
    }

    /* Allocate lists. */
    if ((read_list = PyList_New((Py_ssize_t)0)) == NULL) goto error;
    if ((write_list = PyList_New((Py_ssize_t)0)) == NULL) goto error;
    if ((except_list = PyList_New((Py_ssize_t)0)) == NULL) goto error;

    /* Populate lists */
    for (fd = 0; fd < max_fd + 1; fd++) {
        if (FD_ISSET(fd, &self->read_fd_set)) {
            if ((py_fd = PyInt_FromLong((long)fd)) == NULL) goto error;
            if (PyList_Append(read_list, py_fd) != 0) goto error;
            Py_DECREF(py_fd);
            py_fd = NULL;
        }
        if (FD_ISSET(fd, &self->write_fd_set)) {
            if ((py_fd = PyInt_FromLong((long)fd)) == NULL) goto error;
            if (PyList_Append(write_list, py_fd) != 0) goto error;
            Py_DECREF(py_fd);
            py_fd = NULL;
        }
        if (FD_ISSET(fd, &self->exc_fd_set)) {
            if ((py_fd = PyInt_FromLong((long)fd)) == NULL) goto error;
            if (PyList_Append(except_list, py_fd) != 0) goto error;
            Py_DECREF(py_fd);
            py_fd = NULL;
        }
    }

    /* Return a tuple with the 3 lists */
    ret = Py_BuildValue("(OOO)", read_list, write_list, except_list);
error:
    Py_XDECREF(py_fd);
    Py_XDECREF(except_list);
    Py_XDECREF(write_list);
    Py_XDECREF(read_list);
    return ret;
}


/* --------------- info_read --------------- */

static PyObject *
do_multi_info_read(CurlMultiObject *self, PyObject *args)
{
    PyObject *ret = NULL;
    PyObject *ok_list = NULL, *err_list = NULL;
    CURLMsg *msg;
    int in_queue = 0, num_results = INT_MAX;

    /* Sanity checks */
    if (!PyArg_ParseTuple(args, "|i:info_read", &num_results)) {
        return NULL;
    }
    if (num_results <= 0) {
        PyErr_SetString(ErrorObject, "argument to info_read must be greater than zero");
        return NULL;
    }
    if (check_multi_state(self, 1 | 2, "info_read") != 0) {
        return NULL;
    }

    if ((ok_list = PyList_New((Py_ssize_t)0)) == NULL) goto error;
    if ((err_list = PyList_New((Py_ssize_t)0)) == NULL) goto error;

    /* Loop through all messages */
    while ((msg = curl_multi_info_read(self->multi_handle, &in_queue)) != NULL) {
        CURLcode res;
        CurlObject *co = NULL;

        /* Check for termination as specified by the user */
        if (num_results-- <= 0) {
            break;
        }

        /* Fetch the curl object that corresponds to the curl handle in the message */
        res = curl_easy_getinfo(msg->easy_handle, CURLINFO_PRIVATE, (char **) &co);
        if (res != CURLE_OK || co == NULL) {
            Py_DECREF(err_list);
            Py_DECREF(ok_list);
            CURLERROR_MSG("Unable to fetch curl handle from curl object");
        }
        assert(Py_TYPE(co) == p_Curl_Type);
        if (msg->msg != CURLMSG_DONE) {
            /* FIXME: what does this mean ??? */
        }
        if (msg->data.result == CURLE_OK) {
            /* Append curl object to list of objects which succeeded */
            if (PyList_Append(ok_list, (PyObject *)co) != 0) {
                goto error;
            }
        }
        else {
            /* Create a result tuple that will get added to err_list. */
            PyObject *v = Py_BuildValue("(Ois)", (PyObject *)co, (int)msg->data.result, co->error);
            /* Append curl object to list of objects which failed */
            if (v == NULL || PyList_Append(err_list, v) != 0) {
                Py_XDECREF(v);
                goto error;
            }
            Py_DECREF(v);
        }
    }
    /* Return (number of queued messages, [ok_objects], [error_objects]) */
    ret = Py_BuildValue("(iOO)", in_queue, ok_list, err_list);
error:
    Py_XDECREF(err_list);
    Py_XDECREF(ok_list);
    return ret;
}


/* --------------- select --------------- */

static PyObject *
do_multi_select(CurlMultiObject *self, PyObject *args)
{
    int max_fd = -1, n;
    double timeout = -1.0;
    struct timeval tv, *tvp;
    CURLMcode res;

    if (!PyArg_ParseTuple(args, "d:select", &timeout)) {
        return NULL;
    }
    if (check_multi_state(self, 1 | 2, "select") != 0) {
        return NULL;
    }

    if (timeout < 0 || timeout >= 365 * 24 * 60 * 60) {
        PyErr_SetString(PyExc_OverflowError, "invalid timeout period");
        return NULL;
    } else {
        long seconds = (long)timeout;
        timeout = timeout - (double)seconds;
        assert(timeout >= 0.0); assert(timeout < 1.0);
        tv.tv_sec = seconds;
        tv.tv_usec = (long)(timeout*1000000.0);
        tvp = &tv;
    }

    FD_ZERO(&self->read_fd_set);
    FD_ZERO(&self->write_fd_set);
    FD_ZERO(&self->exc_fd_set);

    res = curl_multi_fdset(self->multi_handle, &self->read_fd_set,
                           &self->write_fd_set, &self->exc_fd_set, &max_fd);
    if (res != CURLM_OK) {
        CURLERROR_MSG("multi_fdset failed");
    }

    if (max_fd < 0) {
        n = 0;
    }
    else {
        Py_BEGIN_ALLOW_THREADS
        n = select(max_fd + 1, &self->read_fd_set, &self->write_fd_set, &self->exc_fd_set, tvp);
        Py_END_ALLOW_THREADS
        /* info: like Python's socketmodule.c we do not raise an exception
         *       if select() fails - we'll leave it to the actual libcurl
         *       socket code to report any errors.
         */
    }

    return PyInt_FromLong(n);
}


static PyObject *do_curlmulti_getstate(CurlMultiObject *self)
{
    PyErr_SetString(PyExc_TypeError, "CurlMulti objects do not support serialization");
    return NULL;
}


static PyObject *do_curlmulti_setstate(CurlMultiObject *self, PyObject *args)
{
    PyErr_SetString(PyExc_TypeError, "CurlMulti objects do not support deserialization");
    return NULL;
}


/*************************************************************************
// type definitions
**************************************************************************/

/* --------------- methods --------------- */

PYCURL_INTERNAL PyMethodDef curlmultiobject_methods[] = {
    {"add_handle", (PyCFunction)do_multi_add_handle, METH_VARARGS, multi_add_handle_doc},
    {"close", (PyCFunction)do_multi_close, METH_NOARGS, multi_close_doc},
    {"fdset", (PyCFunction)do_multi_fdset, METH_NOARGS, multi_fdset_doc},
    {"info_read", (PyCFunction)do_multi_info_read, METH_VARARGS, multi_info_read_doc},
    {"perform", (PyCFunction)do_multi_perform, METH_NOARGS, multi_perform_doc},
    {"socket_action", (PyCFunction)do_multi_socket_action, METH_VARARGS, multi_socket_action_doc},
    {"socket_all", (PyCFunction)do_multi_socket_all, METH_NOARGS, multi_socket_all_doc},
    {"setopt", (PyCFunction)do_multi_setopt, METH_VARARGS, multi_setopt_doc},
    {"timeout", (PyCFunction)do_multi_timeout, METH_NOARGS, multi_timeout_doc},
    {"assign", (PyCFunction)do_multi_assign, METH_VARARGS, multi_assign_doc},
    {"remove_handle", (PyCFunction)do_multi_remove_handle, METH_VARARGS, multi_remove_handle_doc},
    {"select", (PyCFunction)do_multi_select, METH_VARARGS, multi_select_doc},
    {"__getstate__", (PyCFunction)do_curlmulti_getstate, METH_NOARGS, NULL},
    {"__setstate__", (PyCFunction)do_curlmulti_setstate, METH_VARARGS, NULL},
    {NULL, NULL, 0, NULL}
};


/* --------------- setattr/getattr --------------- */


#if PY_MAJOR_VERSION >= 3

PYCURL_INTERNAL PyObject *
do_multi_getattro(PyObject *o, PyObject *n)
{
    PyObject *v;
    assert_multi_state((CurlMultiObject *)o);
    v = PyObject_GenericGetAttr(o, n);
    if( !v && PyErr_ExceptionMatches(PyExc_AttributeError) )
    {
        PyErr_Clear();
        v = my_getattro(o, n, ((CurlMultiObject *)o)->dict,
                        curlmultiobject_constants, curlmultiobject_methods);
    }
    return v;
}

PYCURL_INTERNAL int
do_multi_setattro(PyObject *o, PyObject *n, PyObject *v)
{
    assert_multi_state((CurlMultiObject *)o);
    return my_setattro(&((CurlMultiObject *)o)->dict, n, v);
}

#else /* PY_MAJOR_VERSION >= 3 */

PYCURL_INTERNAL PyObject *
do_multi_getattr(CurlMultiObject *co, char *name)
{
    assert_multi_state(co);
    return my_getattr((PyObject *)co, name, co->dict,
                      curlmultiobject_constants, curlmultiobject_methods);
}

PYCURL_INTERNAL int
do_multi_setattr(CurlMultiObject *co, char *name, PyObject *v)
{
    assert_multi_state(co);
    return my_setattr(&co->dict, name, v);
}

#endif /* PY_MAJOR_VERSION >= 3 */

PYCURL_INTERNAL PyTypeObject CurlMulti_Type = {
#if PY_MAJOR_VERSION >= 3
    PyVarObject_HEAD_INIT(NULL, 0)
#else
    PyObject_HEAD_INIT(NULL)
    0,                          /* ob_size */
#endif
    "pycurl.CurlMulti",         /* tp_name */
    sizeof(CurlMultiObject),    /* tp_basicsize */
    0,                          /* tp_itemsize */
    (destructor)do_multi_dealloc, /* tp_dealloc */
    0,                          /* tp_print */
#if PY_MAJOR_VERSION >= 3
    0,                          /* tp_getattr */
    0,                          /* tp_setattr */
#else
    (getattrfunc)do_multi_getattr,  /* tp_getattr */
    (setattrfunc)do_multi_setattr,  /* tp_setattr */
#endif
    0,                          /* tp_reserved */
    0,                          /* tp_repr */
    0,                          /* tp_as_number */
    0,                          /* tp_as_sequence */
    0,                          /* tp_as_mapping */
    0,                          /* tp_hash  */
    0,                          /* tp_call */
    0,                          /* tp_str */
#if PY_MAJOR_VERSION >= 3
    (getattrofunc)do_multi_getattro, /* tp_getattro */
    (setattrofunc)do_multi_setattro, /* tp_setattro */
#else
    0,                          /* tp_getattro */
    0,                          /* tp_setattro */
#endif
    0,                          /* tp_as_buffer */
    PYCURL_TYPE_FLAGS,          /* tp_flags */
    multi_doc,                   /* tp_doc */
    (traverseproc)do_multi_traverse, /* tp_traverse */
    (inquiry)do_multi_clear,    /* tp_clear */
    0,                          /* tp_richcompare */
    offsetof(CurlMultiObject, weakreflist), /* tp_weaklistoffset */
    0,                          /* tp_iter */
    0,                          /* tp_iternext */
    curlmultiobject_methods,    /* tp_methods */
    0,                          /* tp_members */
    0,                          /* tp_getset */
    0,                          /* tp_base */
    0,                          /* tp_dict */
    0,                          /* tp_descr_get */
    0,                          /* tp_descr_set */
    0,                          /* tp_dictoffset */
    0,                          /* tp_init */
    PyType_GenericAlloc,        /* tp_alloc */
    (newfunc)do_multi_new,      /* tp_new */
    PyObject_GC_Del,            /* tp_free */
};

/* vi:ts=4:et:nowrap
 */


#if defined(WIN32)
PYCURL_INTERNAL int
dup_winsock(int sock, const struct curl_sockaddr *address)
{
    int rv;
    WSAPROTOCOL_INFO pi;

    rv = WSADuplicateSocket(sock, GetCurrentProcessId(), &pi);
    if (rv) {
        return CURL_SOCKET_BAD;
    }

    /* not sure if WSA_FLAG_OVERLAPPED is needed, but it does not seem to hurt */
    return (int) WSASocket(address->family, address->socktype, address->protocol, &pi, 0, WSA_FLAG_OVERLAPPED);
}
#endif

#if defined(WIN32) && ((_WIN32_WINNT < 0x0600) || (NTDDI_VERSION < NTDDI_VISTA))
/*
 * Only Winsock on Vista+ has inet_ntop().
 */
PYCURL_INTERNAL const char *
pycurl_inet_ntop (int family, void *addr, char *string, size_t string_size)
{
    SOCKADDR *sa;
    int       sa_len;
    /* both size_t and DWORD should be unsigned ints */
    DWORD string_size_dword = (DWORD) string_size;

    if (family == AF_INET6) {
        struct sockaddr_in6 sa6;
        memset(&sa6, 0, sizeof(sa6));
        sa6.sin6_family = AF_INET6;
        memcpy(&sa6.sin6_addr, addr, sizeof(sa6.sin6_addr));
        sa = (SOCKADDR*) &sa6;
        sa_len = sizeof(sa6);
    } else if (family == AF_INET) {
        struct sockaddr_in sa4;
        memset(&sa4, 0, sizeof(sa4));
        sa4.sin_family = AF_INET;
        memcpy(&sa4.sin_addr, addr, sizeof(sa4.sin_addr));
        sa = (SOCKADDR*) &sa4;
        sa_len = sizeof(sa4);
    } else {
        errno = EAFNOSUPPORT;
        return NULL;
    }
    if (WSAAddressToString(sa, sa_len, NULL, string, &string_size_dword))
        return NULL;
    return string;
}
#endif

/* vi:ts=4:et:nowrap
 */


#if PY_MAJOR_VERSION >= 3

PYCURL_INTERNAL PyObject *
my_getattro(PyObject *co, PyObject *name, PyObject *dict1, PyObject *dict2, PyMethodDef *m)
{
    PyObject *v = NULL;
    if( dict1 != NULL )
        v = PyDict_GetItem(dict1, name);
    if( v == NULL && dict2 != NULL )
        v = PyDict_GetItem(dict2, name);
    if( v != NULL )
    {
        Py_INCREF(v);
        return v;
    }
    PyErr_Format(PyExc_AttributeError, "trying to obtain a non-existing attribute: %U", name);
    return NULL;
}

PYCURL_INTERNAL int
my_setattro(PyObject **dict, PyObject *name, PyObject *v)
{
    if( *dict == NULL )
    {
        *dict = PyDict_New();
        if( *dict == NULL )
            return -1;
    }
    if (v != NULL)
        return PyDict_SetItem(*dict, name, v);
    else {
        int v = PyDict_DelItem(*dict, name);
        if (v != 0) {
            /* need to convert KeyError to AttributeError */
            if (PyErr_ExceptionMatches(PyExc_KeyError)) {
                PyErr_Format(PyExc_AttributeError, "trying to delete a non-existing attribute: %U", name);
            }
        }
        return v;
    }
}

#else /* PY_MAJOR_VERSION >= 3 */

PYCURL_INTERNAL int
my_setattr(PyObject **dict, char *name, PyObject *v)
{
    if (v == NULL) {
        int rv = -1;
        if (*dict != NULL)
            rv = PyDict_DelItemString(*dict, name);
        if (rv < 0)
            PyErr_Format(PyExc_AttributeError, "trying to delete a non-existing attribute: %s", name);
        return rv;
    }
    if (*dict == NULL) {
        *dict = PyDict_New();
        if (*dict == NULL)
            return -1;
    }
    return PyDict_SetItemString(*dict, name, v);
}

PYCURL_INTERNAL PyObject *
my_getattr(PyObject *co, char *name, PyObject *dict1, PyObject *dict2, PyMethodDef *m)
{
    PyObject *v = NULL;
    if (v == NULL && dict1 != NULL)
        v = PyDict_GetItemString(dict1, name);
    if (v == NULL && dict2 != NULL)
        v = PyDict_GetItemString(dict2, name);
    if (v != NULL) {
        Py_INCREF(v);
        return v;
    }
    return Py_FindMethod(m, co, name);
}

#endif /* PY_MAJOR_VERSION >= 3 */

PYCURL_INTERNAL int
PyListOrTuple_Check(PyObject *v)
{
    int result;
    
    if (PyList_Check(v)) {
        result = PYLISTORTUPLE_LIST;
    } else if (PyTuple_Check(v)) {
        result = PYLISTORTUPLE_TUPLE;
    } else {
        result = PYLISTORTUPLE_OTHER;
    }
    
    return result;
}

PYCURL_INTERNAL Py_ssize_t
PyListOrTuple_Size(PyObject *v, int which)
{
    switch (which) {
    case PYLISTORTUPLE_LIST:
        return PyList_Size(v);
    case PYLISTORTUPLE_TUPLE:
        return PyTuple_Size(v);
    default:
        assert(0);
        return 0;
    }
}

PYCURL_INTERNAL PyObject *
PyListOrTuple_GetItem(PyObject *v, Py_ssize_t i, int which)
{
    switch (which) {
    case PYLISTORTUPLE_LIST:
        return PyList_GetItem(v, i);
    case PYLISTORTUPLE_TUPLE:
        return PyTuple_GetItem(v, i);
    default:
        assert(0);
        return NULL;
    }
}

/* vi:ts=4:et:nowrap
 */



/*************************************************************************
// static utility functions
**************************************************************************/


/* assert some CurlShareObject invariants */
static void
assert_share_state(const CurlShareObject *self)
{
    assert(self != NULL);
    assert(Py_TYPE(self) == p_CurlShare_Type);
#ifdef WITH_THREAD
    assert(self->lock != NULL);
#endif
}


static int
check_share_state(const CurlShareObject *self, int flags, const char *name)
{
    assert_share_state(self);
    return 0;
}


/* constructor */
PYCURL_INTERNAL CurlShareObject *
do_share_new(PyTypeObject *subtype, PyObject *args, PyObject *kwds)
{
    int res;
    CurlShareObject *self;
#ifdef WITH_THREAD
    const curl_lock_function lock_cb = share_lock_callback;
    const curl_unlock_function unlock_cb = share_unlock_callback;
#endif
    int *ptr;
    
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "", empty_keywords)) {
        return NULL;
    }

    /* Allocate python curl-share object */
    self = (CurlShareObject *) subtype->tp_alloc(subtype, 0);
    if (!self) {
        return NULL;
    }

    /* tp_alloc is expected to return zeroed memory */
    for (ptr = (int *) &self->dict;
        ptr < (int *) (((char *) self) + sizeof(CurlShareObject));
        ++ptr) {
            assert(*ptr == 0);
    }
    
#ifdef WITH_THREAD
    self->lock = share_lock_new();
    assert(self->lock != NULL);
#endif

    /* Allocate libcurl share handle */
    self->share_handle = curl_share_init();
    if (self->share_handle == NULL) {
        Py_DECREF(self);
        PyErr_SetString(ErrorObject, "initializing curl-share failed");
        return NULL;
    }

#ifdef WITH_THREAD
    /* Set locking functions and data  */
    res = curl_share_setopt(self->share_handle, CURLSHOPT_LOCKFUNC, lock_cb);
    assert(res == CURLE_OK);
    res = curl_share_setopt(self->share_handle, CURLSHOPT_USERDATA, self);
    assert(res == CURLE_OK);
    res = curl_share_setopt(self->share_handle, CURLSHOPT_UNLOCKFUNC, unlock_cb);
    assert(res == CURLE_OK);
#endif

    return self;
}


PYCURL_INTERNAL int
do_share_traverse(CurlShareObject *self, visitproc visit, void *arg)
{
    int err;
#undef VISIT
#define VISIT(v)    if ((v) != NULL && ((err = visit(v, arg)) != 0)) return err

    VISIT(self->dict);

    return 0;
#undef VISIT
}


/* Drop references that may have created reference cycles. */
PYCURL_INTERNAL int
do_share_clear(CurlShareObject *self)
{
    Py_CLEAR(self->dict);
    return 0;
}


static void
util_share_close(CurlShareObject *self){
    if (self->share_handle != NULL) {
        CURLSH *share_handle = self->share_handle;
        self->share_handle = NULL;
        curl_share_cleanup(share_handle);
    }
}


PYCURL_INTERNAL void
do_share_dealloc(CurlShareObject *self)
{
    PyObject_GC_UnTrack(self);
    Py_TRASHCAN_SAFE_BEGIN(self);

    Py_CLEAR(self->dict);
    util_share_close(self);

#ifdef WITH_THREAD
    share_lock_destroy(self->lock);
#endif

    if (self->weakreflist != NULL) {
        PyObject_ClearWeakRefs((PyObject *) self);
    }
     
    CurlShare_Type.tp_free(self);
    Py_TRASHCAN_SAFE_END(self);
}


static PyObject *
do_share_close(CurlShareObject *self)
{
    if (check_share_state(self, 2, "close") != 0) {
        return NULL;
    }
    util_share_close(self);
    Py_RETURN_NONE;
}


/* setopt, unsetopt*/
/* --------------- unsetopt/setopt/getinfo --------------- */

static PyObject *
do_curlshare_setopt(CurlShareObject *self, PyObject *args)
{
    int option;
    PyObject *obj;

    if (!PyArg_ParseTuple(args, "iO:setopt", &option, &obj))
        return NULL;
    if (check_share_state(self, 1 | 2, "sharesetopt") != 0)
        return NULL;

    /* early checks of option value */
    if (option <= 0)
        goto error;
    if (option >= (int)CURLOPTTYPE_OFF_T + OPTIONS_SIZE)
        goto error;
    if (option % 10000 >= OPTIONS_SIZE)
        goto error;

#if 0 /* XXX - should we ??? */
    /* Handle the case of None */
    if (obj == Py_None) {
        return util_curl_unsetopt(self, option);
    }
#endif

    /* Handle the case of integer arguments */
    if (PyInt_Check(obj)) {
        long d = PyInt_AsLong(obj);
        if (d != CURL_LOCK_DATA_COOKIE && d != CURL_LOCK_DATA_DNS && d != CURL_LOCK_DATA_SSL_SESSION) {
            goto error;
        }
        switch(option) {
        case CURLSHOPT_SHARE:
        case CURLSHOPT_UNSHARE:
            curl_share_setopt(self->share_handle, option, d);
            break;
        default:
            PyErr_SetString(PyExc_TypeError, "integers are not supported for this option");
            return NULL;
        }
        Py_RETURN_NONE;
    }
    /* Failed to match any of the function signatures -- return error */
error:
    PyErr_SetString(PyExc_TypeError, "invalid arguments to setopt");
    return NULL;
}


static PyObject *do_curlshare_getstate(CurlShareObject *self)
{
    PyErr_SetString(PyExc_TypeError, "CurlShare objects do not support serialization");
    return NULL;
}


static PyObject *do_curlshare_setstate(CurlShareObject *self, PyObject *args)
{
    PyErr_SetString(PyExc_TypeError, "CurlShare objects do not support deserialization");
    return NULL;
}


/*************************************************************************
// type definitions
**************************************************************************/

/* --------------- methods --------------- */

PYCURL_INTERNAL PyMethodDef curlshareobject_methods[] = {
    {"close", (PyCFunction)do_share_close, METH_NOARGS, share_close_doc},
    {"setopt", (PyCFunction)do_curlshare_setopt, METH_VARARGS, share_setopt_doc},
    {"__getstate__", (PyCFunction)do_curlshare_getstate, METH_NOARGS, NULL},
    {"__setstate__", (PyCFunction)do_curlshare_setstate, METH_VARARGS, NULL},
    {NULL, NULL, 0, 0}
};


/* --------------- setattr/getattr --------------- */


#if PY_MAJOR_VERSION >= 3

PYCURL_INTERNAL PyObject *
do_share_getattro(PyObject *o, PyObject *n)
{
    PyObject *v;
    assert_share_state((CurlShareObject *)o);
    v = PyObject_GenericGetAttr(o, n);
    if( !v && PyErr_ExceptionMatches(PyExc_AttributeError) )
    {
        PyErr_Clear();
        v = my_getattro(o, n, ((CurlShareObject *)o)->dict,
                        curlshareobject_constants, curlshareobject_methods);
    }
    return v;
}

PYCURL_INTERNAL int
do_share_setattro(PyObject *o, PyObject *n, PyObject *v)
{
    assert_share_state((CurlShareObject *)o);
    return my_setattro(&((CurlShareObject *)o)->dict, n, v);
}

#else /* PY_MAJOR_VERSION >= 3 */

PYCURL_INTERNAL PyObject *
do_share_getattr(CurlShareObject *cso, char *name)
{
    assert_share_state(cso);
    return my_getattr((PyObject *)cso, name, cso->dict,
                      curlshareobject_constants, curlshareobject_methods);
}

PYCURL_INTERNAL int
do_share_setattr(CurlShareObject *so, char *name, PyObject *v)
{
    assert_share_state(so);
    return my_setattr(&so->dict, name, v);
}

#endif /* PY_MAJOR_VERSION >= 3 */

PYCURL_INTERNAL PyTypeObject CurlShare_Type = {
#if PY_MAJOR_VERSION >= 3
    PyVarObject_HEAD_INIT(NULL, 0)
#else
    PyObject_HEAD_INIT(NULL)
    0,                          /* ob_size */
#endif
    "pycurl.CurlShare",         /* tp_name */
    sizeof(CurlShareObject),    /* tp_basicsize */
    0,                          /* tp_itemsize */
    (destructor)do_share_dealloc, /* tp_dealloc */
    0,                          /* tp_print */
#if PY_MAJOR_VERSION >= 3
    0,                          /* tp_getattr */
    0,                          /* tp_setattr */
#else
    (getattrfunc)do_share_getattr,  /* tp_getattr */
    (setattrfunc)do_share_setattr,  /* tp_setattr */
#endif
    0,                          /* tp_reserved */
    0,                          /* tp_repr */
    0,                          /* tp_as_number */
    0,                          /* tp_as_sequence */
    0,                          /* tp_as_mapping */
    0,                          /* tp_hash  */
    0,                          /* tp_call */
    0,                          /* tp_str */
#if PY_MAJOR_VERSION >= 3
    (getattrofunc)do_share_getattro, /* tp_getattro */
    (setattrofunc)do_share_setattro, /* tp_setattro */
#else
    0,                          /* tp_getattro */
    0,                          /* tp_setattro */
#endif
    0,                          /* tp_as_buffer */
    PYCURL_TYPE_FLAGS,          /* tp_flags */
    share_doc,                  /* tp_doc */
    (traverseproc)do_share_traverse, /* tp_traverse */
    (inquiry)do_share_clear,    /* tp_clear */
    0,                          /* tp_richcompare */
    offsetof(CurlShareObject, weakreflist), /* tp_weaklistoffset */
    0,                          /* tp_iter */
    0,                          /* tp_iternext */
    curlshareobject_methods,    /* tp_methods */
    0,                          /* tp_members */
    0,                          /* tp_getset */
    0,                          /* tp_base */
    0,                          /* tp_dict */
    0,                          /* tp_descr_get */
    0,                          /* tp_descr_set */
    0,                          /* tp_dictoffset */
    0,                          /* tp_init */
    PyType_GenericAlloc,        /* tp_alloc */
    (newfunc)do_share_new,      /* tp_new */
    PyObject_GC_Del,            /* tp_free */
};

/* vi:ts=4:et:nowrap
 */


/*************************************************************************
// python utility functions
**************************************************************************/

PYCURL_INTERNAL int
PyText_AsStringAndSize(PyObject *obj, char **buffer, Py_ssize_t *length, PyObject **encoded_obj)
{
    if (PyByteStr_Check(obj)) {
        *encoded_obj = NULL;
        return PyByteStr_AsStringAndSize(obj, buffer, length);
    } else {
        int rv;
        assert(PyUnicode_Check(obj));
        *encoded_obj = PyUnicode_AsEncodedString(obj, "ascii", "strict");
        if (*encoded_obj == NULL) {
            return -1;
        }
        rv = PyByteStr_AsStringAndSize(*encoded_obj, buffer, length);
        if (rv != 0) {
            /* If we free the object, pointer must be reset to NULL */
            Py_CLEAR(*encoded_obj);
        }
        return rv;
    }
}


/* Like PyString_AsString(), but set an exception if the string contains
 * embedded NULs. Actually PyString_AsStringAndSize() already does that for
 * us if the `len' parameter is NULL - see Objects/stringobject.c.
 */

PYCURL_INTERNAL char *
PyText_AsString_NoNUL(PyObject *obj, PyObject **encoded_obj)
{
    char *s = NULL;
    Py_ssize_t r;
    r = PyText_AsStringAndSize(obj, &s, NULL, encoded_obj);
    if (r != 0)
        return NULL;    /* exception already set */
    assert(s != NULL);
    return s;
}


/* Returns true if the object is of a type that can be given to
 * curl_easy_setopt and such - either a byte string or a Unicode string
 * with ASCII code points only.
 */
#if PY_MAJOR_VERSION >= 3
PYCURL_INTERNAL int
PyText_Check(PyObject *o)
{
    return PyUnicode_Check(o) || PyBytes_Check(o);
}
#else
PYCURL_INTERNAL int
PyText_Check(PyObject *o)
{
    return PyUnicode_Check(o) || PyString_Check(o);
}
#endif

PYCURL_INTERNAL PyObject *
PyText_FromString_Ignore(const char *string)
{
    PyObject *v;

#if PY_MAJOR_VERSION >= 3
    PyObject *u;
    
    v = Py_BuildValue("y", string);
    if (v == NULL) {
        return NULL;
    }
    
    u = PyUnicode_FromEncodedObject(v, NULL, "replace");
    Py_DECREF(v);
    return u;
#else
    v = Py_BuildValue("s", string);
    return v;
#endif
}


#ifdef WITH_THREAD

PYCURL_INTERNAL PyThreadState *
pycurl_get_thread_state(const CurlObject *self)
{
    /* Get the thread state for callbacks to run in.
     * This is either `self->state' when running inside perform() or
     * `self->multi_stack->state' when running inside multi_perform().
     * When the result is != NULL we also implicitly assert
     * a valid `self->handle'.
     */
    if (self == NULL)
        return NULL;
    assert(Py_TYPE(self) == p_Curl_Type);
    if (self->state != NULL)
    {
        /* inside perform() */
        assert(self->handle != NULL);
        if (self->multi_stack != NULL) {
            assert(self->multi_stack->state == NULL);
        }
        return self->state;
    }
    if (self->multi_stack != NULL && self->multi_stack->state != NULL)
    {
        /* inside multi_perform() */
        assert(self->handle != NULL);
        assert(self->multi_stack->multi_handle != NULL);
        assert(self->state == NULL);
        return self->multi_stack->state;
    }
    return NULL;
}


PYCURL_INTERNAL PyThreadState *
pycurl_get_thread_state_multi(const CurlMultiObject *self)
{
    /* Get the thread state for callbacks to run in when given
     * multi handles instead of regular handles
     */
    if (self == NULL)
        return NULL;
    assert(Py_TYPE(self) == p_CurlMulti_Type);
    if (self->state != NULL)
    {
        /* inside multi_perform() */
        assert(self->multi_handle != NULL);
        return self->state;
    }
    return NULL;
}


PYCURL_INTERNAL int
pycurl_acquire_thread(const CurlObject *self, PyThreadState **state)
{
    *state = pycurl_get_thread_state(self);
    if (*state == NULL)
        return 0;
    PyEval_AcquireThread(*state);
    return 1;
}


PYCURL_INTERNAL int
pycurl_acquire_thread_multi(const CurlMultiObject *self, PyThreadState **state)
{
    *state = pycurl_get_thread_state_multi(self);
    if (*state == NULL)
        return 0;
    PyEval_AcquireThread(*state);
    return 1;
}


PYCURL_INTERNAL void
pycurl_release_thread(PyThreadState *state)
{
    PyEval_ReleaseThread(state);
}

/*************************************************************************
// SSL TSL
**************************************************************************/

#ifdef PYCURL_NEED_OPENSSL_TSL

#if OPENSSL_VERSION_NUMBER < 0x10100000
static PyThread_type_lock *pycurl_openssl_tsl = NULL;

static void
pycurl_ssl_lock(int mode, int n, const char * file, int line)
{
    if (mode & CRYPTO_LOCK) {
        PyThread_acquire_lock(pycurl_openssl_tsl[n], 1);
    } else {
        PyThread_release_lock(pycurl_openssl_tsl[n]);
    }
}

#if OPENSSL_VERSION_NUMBER >= 0x10000000
/* use new CRYPTO_THREADID API. */
static void
pycurl_ssl_threadid_callback(CRYPTO_THREADID *id)
{
    CRYPTO_THREADID_set_numeric(id, (unsigned long)PyThread_get_thread_ident());
}
#else
/* deprecated CRYPTO_set_id_callback() API. */
static unsigned long
pycurl_ssl_id(void)
{
    return (unsigned long) PyThread_get_thread_ident();
}
#endif
#endif

PYCURL_INTERNAL int
pycurl_ssl_init(void)
{
#if OPENSSL_VERSION_NUMBER < 0x10100000
    int i, c = CRYPTO_num_locks();

    pycurl_openssl_tsl = PyMem_New(PyThread_type_lock, c);
    if (pycurl_openssl_tsl == NULL) {
        PyErr_NoMemory();
        return -1;
    }
    memset(pycurl_openssl_tsl, 0, sizeof(PyThread_type_lock) * c);

    for (i = 0; i < c; ++i) {
        pycurl_openssl_tsl[i] = PyThread_allocate_lock();
        if (pycurl_openssl_tsl[i] == NULL) {
            for (--i; i >= 0; --i) {
                PyThread_free_lock(pycurl_openssl_tsl[i]);
            }
            PyMem_Free(pycurl_openssl_tsl);
            PyErr_NoMemory();
            return -1;
        }
    }

#if OPENSSL_VERSION_NUMBER >= 0x10000000
    CRYPTO_THREADID_set_callback(pycurl_ssl_threadid_callback);
#else
    CRYPTO_set_id_callback(pycurl_ssl_id);
#endif
    CRYPTO_set_locking_callback(pycurl_ssl_lock);
#endif
    return 0;
}

PYCURL_INTERNAL void
pycurl_ssl_cleanup(void)
{
#if OPENSSL_VERSION_NUMBER < 0x10100000
    if (pycurl_openssl_tsl) {
        int i, c = CRYPTO_num_locks();

#if OPENSSL_VERSION_NUMBER >= 0x10000000
        CRYPTO_THREADID_set_callback(NULL);
#else
        CRYPTO_set_id_callback(NULL);
#endif
        CRYPTO_set_locking_callback(NULL);

        for (i = 0; i < c; ++i) {
            PyThread_free_lock(pycurl_openssl_tsl[i]);
        }

        PyMem_Free(pycurl_openssl_tsl);
        pycurl_openssl_tsl = NULL;
    }
#endif
}
#endif

#ifdef PYCURL_NEED_GNUTLS_TSL
static int
pycurl_ssl_mutex_create(void **m)
{
    if ((*((PyThread_type_lock *) m) = PyThread_allocate_lock()) == NULL) {
        return -1;
    } else {
        return 0;
    }
}

static int
pycurl_ssl_mutex_destroy(void **m)
{
    PyThread_free_lock(*((PyThread_type_lock *) m));
    return 0;
}

static int
pycurl_ssl_mutex_lock(void **m)
{
    return !PyThread_acquire_lock(*((PyThread_type_lock *) m), 1);
}

static int
pycurl_ssl_mutex_unlock(void **m)
{
    PyThread_release_lock(*((PyThread_type_lock *) m));
    return 0;
}

static struct gcry_thread_cbs pycurl_gnutls_tsl = {
    GCRY_THREAD_OPTION_USER,
    NULL,
    pycurl_ssl_mutex_create,
    pycurl_ssl_mutex_destroy,
    pycurl_ssl_mutex_lock,
    pycurl_ssl_mutex_unlock
};

PYCURL_INTERNAL int
pycurl_ssl_init(void)
{
    gcry_control(GCRYCTL_SET_THREAD_CBS, &pycurl_gnutls_tsl);
    return 0;
}

PYCURL_INTERNAL void
pycurl_ssl_cleanup(void)
{
    return;
}
#endif

/* mbedTLS */

#ifdef PYCURL_NEED_MBEDTLS_TSL
static int
pycurl_ssl_mutex_create(void **m)
{
    if ((*((PyThread_type_lock *) m) = PyThread_allocate_lock()) == NULL) {
        return -1;
    } else {
        return 0;
    }
}

static int
pycurl_ssl_mutex_destroy(void **m)
{
    PyThread_free_lock(*((PyThread_type_lock *) m));
    return 0;
}

static int
pycurl_ssl_mutex_lock(void **m)
{
    return !PyThread_acquire_lock(*((PyThread_type_lock *) m), 1);
}

PYCURL_INTERNAL int
pycurl_ssl_init(void)
{
    return 0;
}

PYCURL_INTERNAL void
pycurl_ssl_cleanup(void)
{
    return;
}
#endif

/*************************************************************************
// CurlShareObject
**************************************************************************/

PYCURL_INTERNAL void
share_lock_lock(ShareLock *lock, curl_lock_data data)
{
    PyThread_acquire_lock(lock->locks[data], 1);
}

PYCURL_INTERNAL void
share_lock_unlock(ShareLock *lock, curl_lock_data data)
{
    PyThread_release_lock(lock->locks[data]);
}

PYCURL_INTERNAL ShareLock *
share_lock_new(void)
{
    int i;
    ShareLock *lock = PyMem_New(ShareLock, 1);
    if (lock == NULL) {
        PyErr_NoMemory();
        return NULL;
    }

    for (i = 0; i < CURL_LOCK_DATA_LAST; ++i) {
        lock->locks[i] = PyThread_allocate_lock();
        if (lock->locks[i] == NULL) {
            PyErr_NoMemory();
            goto error;
        }
    }
    return lock;

error:
    for (--i; i >= 0; --i) {
        PyThread_free_lock(lock->locks[i]);
        lock->locks[i] = NULL;
    }
    PyMem_Free(lock);
    return NULL;
}

PYCURL_INTERNAL void
share_lock_destroy(ShareLock *lock)
{
    int i;

    assert(lock);
    for (i = 0; i < CURL_LOCK_DATA_LAST; ++i){
        assert(lock->locks[i] != NULL);
        PyThread_free_lock(lock->locks[i]);
    }
    PyMem_Free(lock);
    lock = NULL;
}

PYCURL_INTERNAL void
share_lock_callback(CURL *handle, curl_lock_data data, curl_lock_access locktype, void *userptr)
{
    CurlShareObject *share = (CurlShareObject*)userptr;
    share_lock_lock(share->lock, data);
}

PYCURL_INTERNAL void
share_unlock_callback(CURL *handle, curl_lock_data data, void *userptr)
{
    CurlShareObject *share = (CurlShareObject*)userptr;
    share_lock_unlock(share->lock, data);
}

#else /* WITH_THREAD */

#if defined(PYCURL_NEED_SSL_TSL)
PYCURL_INTERNAL void
pycurl_ssl_init(void)
{
    return 0;
}

PYCURL_INTERNAL void
pycurl_ssl_cleanup(void)
{
    return;
}
#endif

#endif /* WITH_THREAD */

/* vi:ts=4:et:nowrap
 */


static PyObject *
create_error_object(CurlObject *self, int code)
{
    PyObject *s, *v;
    
    s = PyText_FromString_Ignore(self->error);
    if (s == NULL) {
        return NULL;
    }
    v = Py_BuildValue("(iO)", code, s);
    if (v == NULL) {
        Py_DECREF(s);
        return NULL;
    }
    return v;
}

PYCURL_INTERNAL void
create_and_set_error_object(CurlObject *self, int code)
{
    PyObject *e;
    
    self->error[sizeof(self->error) - 1] = 0;
    e = create_error_object(self, code);
    if (e != NULL) {
        PyErr_SetObject(ErrorObject, e);
        Py_DECREF(e);
    }
}
