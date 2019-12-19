#include <uvtls.h>

#include <assert.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/conf.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

#if defined(OPENSSL_VERSION_NUMBER) && !defined(LIBRESSL_VERSION_NUMBER)
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
#define UVTLS_CLIENT_METHOD TLS_client_method
#define UVTLS_SERVER_METHOD TLS_server_method
#else
#define UVTLS_CLIENT_METHOD SSLv23_client_method
#define UVTLS_SERVER_METHOD SSLv23_server_method
#endif
#else
#if (LIBRESSL_VERSION_NUMBER >= 0x20302000L)
#define UVTLS_CLIENT_METHOD TLS_client_method
#define UVTLS_SERVER_METHOD TLS_server_method
#else
#define UVTLS_CLIENT_METHOD SSLv23_client_method
#define UVTLS_SERVER_METHOD SSLv23_server_method
#endif
#endif

#define UVTLS_HANDSHAKE_MAX_BUFFER_SIZE UVTLS_RING_BUFFER_BLOCK_SIZE

#define PRINT_INFO(ssl, w, flag, msg)                                          \
  do {                                                                         \
    if (w & flag) {                                                            \
      fprintf(stderr, "%s - %s - %s\n", msg, SSL_state_string(ssl),            \
              SSL_state_string_long(ssl));                                     \
    }                                                                          \
  } while (0);

static void info_callback(const SSL *ssl, int where, int ret) {
  if (ret == 0) {
    fprintf(stderr, "info_callback, error occurred.\n");
    return;
  }
  PRINT_INFO(ssl, where, SSL_CB_LOOP, "LOOP");
  PRINT_INFO(ssl, where, SSL_CB_EXIT, "EXIT");
  PRINT_INFO(ssl, where, SSL_CB_READ, "READ");
  PRINT_INFO(ssl, where, SSL_CB_WRITE, "WRITE");
  PRINT_INFO(ssl, where, SSL_CB_ALERT, "ALERT");
  PRINT_INFO(ssl, where, SSL_CB_HANDSHAKE_DONE, "HANDSHAKE DONE");
}
#undef PRINT_INFO

static uv_once_t lib_init_guard__ = UV_ONCE_INIT;

static void lib_cleanup() {
  RAND_cleanup();
  ENGINE_cleanup();
  CONF_modules_unload(1);
  CONF_modules_free();
  EVP_cleanup();
  ERR_free_strings();
  CRYPTO_cleanup_all_ex_data();
  CRYPTO_set_locking_callback(NULL);
  CRYPTO_set_id_callback(NULL);
#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
  ERR_remove_thread_state(NULL);
#endif
}

static void lib_init() {
  SSL_library_init();
  SSL_load_error_strings();
  OpenSSL_add_all_algorithms();
  atexit(lib_cleanup);
}

static int ringbuffer_bio_create(BIO *bio);
static int ringbuffer_bio_destroy(BIO *bio);
static int ringbuffer_bio_read(BIO *bio, char *out, int len);
static int ringbuffer_bio_write(BIO *bio, const char *data, int len);
static int ringbuffer_bio_puts(BIO *bio, const char *str);
static int ringbuffer_bio_gets(BIO *bio, char *out, int size);
static long ringbuffer_bio_ctrl(BIO *bio, int cmd, long num, void *ptr);

#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
const BIO_METHOD method__ = {BIO_TYPE_MEM,           "Ring Buffer",
                             ringbuffer_bio_write,   ringbuffer_bio_read,
                             ringbuffer_bio_puts,    ringbuffer_bio_gets,
                             ringbuffer_bio_ctrl,    ringbuffer_bio_create,
                             ringbuffer_bio_destroy, NULL};
#else
static BIO_METHOD *method__ = NULL;
void ringbuffer_bio_init() {
  method__ = BIO_meth_new(BIO_TYPE_MEM, "Ring Buffer");
  if (method__) {
    BIO_meth_set_write(method__, ringbuffer_bio_write);
    BIO_meth_set_read(method__, ringbuffer_bio_read);
    BIO_meth_set_puts(method__, ringbuffer_bio_puts);
    BIO_meth_set_gets(method__, ringbuffer_bio_gets);
    BIO_meth_set_ctrl(method__, ringbuffer_bio_ctrl);
    BIO_meth_set_create(method__, ringbuffer_bio_create);
    BIO_meth_set_destroy(method__, ringbuffer_bio_destroy);
  }
}
#endif

static uv_once_t ringbuffer_init_guard__ = UV_ONCE_INIT;

static void ringbuffer_bio_init_once() {
  uv_once(&ringbuffer_init_guard__, ringbuffer_bio_init);
}

uvtls_ringbuffer_t *ringbuffer_from_bio(BIO *bio) {
  void *data = BIO_get_data(bio);
  assert(data && "BIO data field should not be NULL");
  return (uvtls_ringbuffer_t *)data;
}

int ringbuffer_bio_create(BIO *bio) {
  BIO_set_shutdown(bio, 1);
  BIO_set_init(bio, 1);
  return 1;
}

int ringbuffer_bio_destroy(BIO *bio) {
  if (bio == NULL) {
    return 0;
  }
  uvtls_ringbuffer_destroy(ringbuffer_from_bio(bio));
  return 1;
}

int ringbuffer_bio_read(BIO *bio, char *out, int len) {
  int bytes;
  BIO_clear_retry_flags(bio);

  uvtls_ringbuffer_t *rb = ringbuffer_from_bio(bio);
  bytes = uvtls_ringbuffer_read(rb, out, len);

  if (bytes == 0) {
    assert(rb->ret <= INT_MAX && "Value is too big for ring buffer BIO read");
    bytes = (int)rb->ret;
    if (bytes != 0) {
      BIO_set_retry_read(bio);
    }
  }

  return bytes;
}

int ringbuffer_bio_write(BIO *bio, const char *data, int len) {
  BIO_clear_retry_flags(bio);
  uvtls_ringbuffer_write(ringbuffer_from_bio(bio), data, len);
  return len;
}

int ringbuffer_bio_puts(BIO *bio, const char *str) { abort(); }

int ringbuffer_bio_gets(BIO *bio, char *out, int size) { abort(); }

long ringbuffer_bio_ctrl(BIO *bio, int cmd, long num, void *ptr) {
  long ret = 1;

  uvtls_ringbuffer_t *rb = ringbuffer_from_bio(bio);

  switch (cmd) {
  case BIO_CTRL_RESET:
    uvtls_ringbuffer_reset(rb);
    break;
  case BIO_CTRL_EOF:
    ret = (uvtls_ringbuffer_size(rb) == 0);
    break;
  case BIO_C_SET_BUF_MEM_EOF_RETURN:
    rb->ret = num;
    break;
  case BIO_CTRL_INFO:
    ret = uvtls_ringbuffer_size(rb);
    if (ptr != NULL) {
      *(void **)ptr = NULL;
    }
    break;
  case BIO_C_SET_BUF_MEM:
    assert(0 && "Can't use SET_BUF_MEM_PTR with RingBufferBio");
    abort();
    break;
  case BIO_C_GET_BUF_MEM_PTR:
    assert(0 && "Can't use GET_BUF_MEM_PTR with RingBufferBio");
    ret = 0;
    break;
  case BIO_CTRL_GET_CLOSE:
    ret = BIO_get_shutdown(bio);
    break;
  case BIO_CTRL_SET_CLOSE:
    assert(num <= INT_MAX && num >= INT_MIN &&
           "BIO ctrl value is too big or too small");
    BIO_set_shutdown(bio, (int)num);
    break;
  case BIO_CTRL_WPENDING:
    ret = 0;
    break;
  case BIO_CTRL_PENDING:
    ret = uvtls_ringbuffer_size(rb);
    break;
  case BIO_CTRL_DUP:
  case BIO_CTRL_FLUSH:
    ret = 1;
    break;
  case BIO_CTRL_PUSH:
  case BIO_CTRL_POP:
  default:
    ret = 0;
    break;
  }
  return ret;
}

BIO *create_bio(uvtls_ringbuffer_t *rb) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
  BIO *bio = BIO_new(const_cast<BIO_METHOD *>(&method_));
#else
  BIO *bio = BIO_new(method__);
#endif
  BIO_set_data(bio, rb);
  return bio;
}

static X509 *load_cert(const char *cert, size_t length) {
  if (length > INT_MAX) {
    return NULL;
  }
  BIO *bio = BIO_new_mem_buf(cert, (int)length);
  if (bio == NULL) {
    return NULL;
  }

  X509 *x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL);
  if (x509 == NULL) {
    /* FIXME: error handling */
  }

  BIO_free_all(bio);

  return x509;
}

static EVP_PKEY *load_key(const char *key, size_t length) {
  if (length > INT_MAX) {
    return NULL;
  }
  BIO *bio = BIO_new_mem_buf(key, (int)length);
  if (bio == NULL) {
    return NULL;
  }

  EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
  if (pkey == NULL) {
    /* FIXME: error handling */
  }

  BIO_free_all(bio);

  return pkey;
}

typedef struct uvtls_session_s uvtls_session_t;

struct uvtls_session_s {
  SSL *ssl;
  BIO *incoming_bio;
  BIO *outgoing_bio;
};

static uvtls_session_t *uvtls_session_create(SSL_CTX *ssl_ctx,
                                             uvtls_ringbuffer_t *incoming,
                                             uvtls_ringbuffer_t *outgoing) {
  uvtls_session_t *session = (uvtls_session_t *)malloc(sizeof(uvtls_session_t));

  SSL_CTX_up_ref(ssl_ctx);

  session->ssl = SSL_new(ssl_ctx);
  session->incoming_bio = create_bio(incoming);
  session->outgoing_bio = create_bio(outgoing);

  SSL_set_bio(session->ssl, session->incoming_bio, session->outgoing_bio);

  return session;
}

static void on_handshake_write(uv_write_t *req, int status);

static void ssl_print_error() {
  const char *data;
  int flags;
  unsigned long err;
  while ((err = ERR_get_error_line_data(NULL, NULL, &data, &flags)) != 0) {
    char buf[256];
    ERR_error_string_n(err, buf, sizeof(buf));
    fprintf(stderr, "%s:%s\n", buf, flags & ERR_TXT_STRING ? data : "");
  }
}

static int do_handshake(uvtls_t *tls) {
  uvtls_session_t *session = (uvtls_session_t *)tls->impl;

  int rc = SSL_do_handshake(session->ssl);
  if (rc <= 0) {
    int err = SSL_get_error(session->ssl, rc);
    if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_NONE) {
      ssl_print_error();
      return -1;
    }
  }

  char data[UVTLS_HANDSHAKE_MAX_BUFFER_SIZE];
  int size =
      BIO_read(session->outgoing_bio, data, UVTLS_HANDSHAKE_MAX_BUFFER_SIZE);
  if (size > 0) {
    uv_write_t *req = (uv_write_t *)malloc(sizeof(uv_write_t));
    req->data = (char *)malloc((size_t)size);
    memcpy(req->data, data, (size_t)size);

    uv_buf_t bufs;
    bufs.base = req->data;
    bufs.len = (size_t)size;
    return uv_write(req, (uv_stream_t *)tls->stream, &bufs, 1,
                    on_handshake_write);
  }

  return 0;
}

static int verify(uvtls_t *tls) {
  int verify_flags = tls->context->verify_flags;
  if (!verify_flags) {
    return 0;
  }

  int result = -1; /* FIXME: error code */
  uvtls_session_t *session = (uvtls_session_t *)tls->impl;

  X509 *peer_cert = SSL_get_peer_certificate(session->ssl);
  if (peer_cert == NULL) {
    goto error;
  }

  if (verify_flags & UVTLS_VERIFY_PEER_CERT) {
    long rc = SSL_get_verify_result(session->ssl);
    if (rc != X509_V_OK) {
      goto error;
    }
  }

  if (verify_flags & UVTLS_VERIFY_PEER_IDENTITY) {
    goto error;
  }

  return 0;

error:
  X509_free(peer_cert);
  return result;
}

static void on_alloc(uv_handle_t *handle, size_t suggested_size,
                     uv_buf_t *buf) {
  uvtls_t *tls = (uvtls_t *)handle->data;
  buf->len = (size_t)uvtls_ringbuffer_tail_block(&tls->incoming, &buf->base,
                                                 (int)suggested_size);
}

static void on_handshake_write(uv_write_t *req, int status) {
  free(req->data);
  free(req);
}

static void on_handshake_connect_read(uv_stream_t *stream, ssize_t nread,
                                      const uv_buf_t *buf) {

  uvtls_t *tls = (uvtls_t *)stream->data;
  uvtls_session_t *session = (uvtls_session_t *)tls->impl;

  if ((nread == UV_EOF && !SSL_is_init_finished(session->ssl)) ||
      (nread != UV_EOF && nread < 0)) {
    uv_read_stop(stream);
    tls->connect_req->cb(tls->connect_req, -1);
    return;
  }

  uvtls_ringbuffer_tail_block_commit(&tls->incoming, (int)nread);

  int rc = do_handshake(tls);
  if (rc != 0) {
    uv_read_stop(stream);
    tls->connect_req->cb(tls->connect_req, -1);
  } else if (SSL_is_init_finished(session->ssl)) {
    uv_read_stop(stream);
    tls->connect_req->cb(tls->connect_req, verify(tls));
  }
}

static void on_handshake_accept_read(uv_stream_t *stream, ssize_t nread,
                                     const uv_buf_t *buf) {

  uvtls_t *tls = (uvtls_t *)stream->data;
  uvtls_session_t *session = (uvtls_session_t *)tls->impl;

  if ((nread == UV_EOF && !SSL_is_init_finished(session->ssl)) ||
      (nread != UV_EOF && nread < 0)) {
    uv_read_stop(stream);
    tls->accept_cb(tls, -1);
    return;
  }

  uvtls_ringbuffer_tail_block_commit(&tls->incoming, (int)nread);

  int rc = do_handshake(tls);
  if (rc != 0) {
    uv_read_stop(stream);
    tls->accept_cb(tls, -1);
  } else if (SSL_is_init_finished(session->ssl)) {
    uv_read_stop(stream);
    tls->accept_cb(tls, 0);
  }
}

static void do_read(uvtls_t *tls) {
  char data[UVTLS_HANDSHAKE_MAX_BUFFER_SIZE];
  ssize_t nread;

  uvtls_session_t *session = (uvtls_session_t *)tls->impl;
  uv_buf_t buf = uv_buf_init(data, UVTLS_HANDSHAKE_MAX_BUFFER_SIZE);
  while ((nread = SSL_read(session->ssl, data,
                           UVTLS_HANDSHAKE_MAX_BUFFER_SIZE)) > 0) {
    tls->read_cb(tls, nread, &buf);
  }
}

static void on_read(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
  uvtls_t *tls = (uvtls_t *)stream->data;

  if (nread < 0) {
    tls->read_cb(tls, nread, NULL);
    return;
  }

  uvtls_ringbuffer_tail_block_commit(&tls->incoming, (int)nread);

  do_read(tls);
}

static void on_write(uv_write_t *req, int status) {
  uvtls_write_t *write_req = (uvtls_write_t *)req->data;
  uvtls_ringbuffer_head_blocks_commit(&write_req->tls->outgoing,
                                      write_req->to_commit);
  write_req->cb(write_req, status);
}

int uvtls_context_init(uvtls_context_t *context, int flags) {
  if (flags & UVTLS_CONTEXT_LIB_INIT) {
    uv_once(&lib_init_guard__, lib_init);
  }
  SSL_CTX *ssl_ctx = SSL_CTX_new((flags & UVTLS_CONTEXT_SERVER_MODE)
                                     ? UVTLS_SERVER_METHOD()
                                     : UVTLS_CLIENT_METHOD()); /* FIXME: OOM */

  context->impl = ssl_ctx;
  context->verify_flags = UVTLS_VERIFY_PEER_CERT;

  if (flags & UVTLS_CONTEXT_DEBUG) {
    SSL_CTX_set_info_callback(ssl_ctx, info_callback);
  }

  SSL_CTX_set_ecdh_auto(ssl_ctx, 1);
  SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_NONE, NULL);
  return 0;
}

void uvtls_context_close(uvtls_context_t *context) {
  SSL_CTX_free((SSL_CTX *)context->impl);
}

void uvtls_context_set_verify_flags(uvtls_context_t *context,
                                    int verify_flags) {
  context->verify_flags = verify_flags;
}

int uvtls_context_add_trusted_cert(uvtls_context_t *context, const char *cert,
                                   size_t length) {

  X509 *x509 = load_cert(cert, length);
  if (x509 == NULL) {
    return -1; /* FIXME: error code */
  }

  X509_STORE *trusted_store = SSL_CTX_get_cert_store((SSL_CTX *)context->impl);
  X509_STORE_add_cert(trusted_store, x509);
  X509_free(x509);
  return 0;
}

int uvtls_context_set_cert(uvtls_context_t *context, const char *cert,
                           size_t length) {
  X509 *x509 = load_cert(cert, length);
  if (x509 == NULL) {
    return -1; /* FIXME: error code */
  }

  SSL_CTX_use_certificate((SSL_CTX *)context->impl, x509);
  X509_free(x509);
  return 0;
}

int uvtls_context_set_private_key(uvtls_context_t *context, const char *key,
                                  size_t length) {
  EVP_PKEY *pkey = load_key(key, length);
  if (pkey == NULL) {
    return -1; /* FIXME: error code */
  }

  SSL_CTX_use_PrivateKey((SSL_CTX *)context->impl, pkey);
  EVP_PKEY_free(pkey);
  return 0;
}

int uvtls_init(uvtls_t *tls, uvtls_context_t *context, uv_stream_t *stream) {
  ringbuffer_bio_init_once();
  tls->stream = stream;
  tls->context = context;
  tls->hostname[0] = '\0';
  tls->read_cb = NULL;
  tls->connect_req = NULL;
  tls->connection_cb = NULL;
  /* FIXME: OOM */
  uvtls_ringbuffer_init(&tls->incoming);
  uvtls_ringbuffer_init(&tls->outgoing);
  tls->impl = uvtls_session_create((SSL_CTX *)context->impl, &tls->incoming,
                                   &tls->outgoing);
  if (!tls->impl)
    return UV_ENOMEM;
  return 0;
}

void uvtls_close(uvtls_t *tls) {
  uvtls_read_stop(tls);

  uvtls_session_t *session = (uvtls_session_t *)tls->impl;
  SSL_CTX_free(SSL_get_SSL_CTX(session->ssl));
  SSL_free(session->ssl);
  free(session);
}

int uvtls_set_hostname(uvtls_t *tls, const char *hostname, size_t length) {
  if (length + 1 > sizeof(tls->hostname)) {
    return -1; /* FIXME: error code */
  }
  tls->hostname[length] = '\0';
  memcpy(tls->hostname, hostname, length);
  return 0;
}

int uvtls_connect(uvtls_connect_t *req, uvtls_t *tls, uvtls_connect_cb cb) {
  uvtls_session_t *session = (uvtls_session_t *)tls->impl;

  req->tls = tls;
  req->cb = cb;
  tls->stream->data = tls;
  tls->connect_req = req;

  SSL_set_connect_state(session->ssl);

  int rc = do_handshake(tls);
  assert(!SSL_is_init_finished(session->ssl) &&
         "Handshake shouldn't be finished");
  if (rc != 0) {
    return -1;
  }

  return uv_read_start(tls->stream, on_alloc, on_handshake_connect_read);
}

static void on_connection(uv_stream_t *server, int status) {
  uvtls_t *tls = (uvtls_t *)server->data;
  tls->connection_cb(tls, status);
}

int uvtls_listen(uvtls_t *tls, int backlog, uvtls_connection_cb cb) {
  tls->stream->data = tls;
  tls->connection_cb = cb;
  return uv_listen(tls->stream, backlog, on_connection);
}

int uvtls_accept(uvtls_t *server, uvtls_t *client, uvtls_accept_cb cb) {
  uvtls_session_t *session = (uvtls_session_t *)client->impl;

  int rc = uv_accept(server->stream, client->stream);
  if (rc != 0) {
    return -1;
  }

  SSL_set_accept_state(session->ssl);

  rc = do_handshake(client);
  assert(!SSL_is_init_finished(session->ssl) &&
         "Handshake shouldn't be finished");
  if (rc != 0) {
    return -1;
  }

  client->stream->data = client;
  client->accept_cb = cb;
  return uv_read_start(client->stream, on_alloc, on_handshake_accept_read);
}

int uvtls_read_start(uvtls_t *tls, uvtls_read_cb read_cb) {
  tls->stream->data = tls;
  tls->read_cb = read_cb;

  do_read(tls); /* Process existing ring buffer data  */

  return uv_read_start(tls->stream, on_alloc, on_read);
}

int uvtls_read_stop(uvtls_t *tls) { return uv_read_stop(tls->stream); }

int uvtls_write(uvtls_write_t *req, uvtls_t *tls, const uv_buf_t bufs[],
                unsigned int nbufs, uvtls_write_cb cb) {
  req->req.data = req;
  req->cb = cb;
  req->tls = tls;
  tls->stream->data = tls;

  uvtls_session_t *session = (uvtls_session_t *)tls->impl;
  for (unsigned int i = 0; i < nbufs; ++i) {
    SSL_write(session->ssl, bufs[i].base, (int)bufs[i].len);
  }

  uv_buf_t temp[2];
  int n = uvtls_ringbuffer_head_blocks(&tls->outgoing, temp, 2);

  req->to_commit = 0;
  for (int i = 0; i < n; ++i)
    req->to_commit += temp[i].len;
  return uv_write(&req->req, (uv_stream_t *)tls->stream, temp, (unsigned int)n,
                  on_write);
}
