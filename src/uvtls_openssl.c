#include <uvtls.h>

#include <assert.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/conf.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

#if defined(OPENSSL_VERSION_NUMBER) && !defined(LIBRESSL_VERSION_NUMBER)
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
#define SSL_CLIENT_METHOD TLS_client_method
#else
#define SSL_CLIENT_METHOD SSLv23_client_method
#endif
#else
#if (LIBRESSL_VERSION_NUMBER >= 0x20302000L)
#define SSL_CLIENT_METHOD TLS_client_method
#else
#define SSL_CLIENT_METHOD SSLv23_client_method
#endif
#endif

#define SSL_HANDSHAKE_MAX_BUFFER_SIZE (16 * 1024 + 5)

#ifdef SSL_DEBUG
#define SSL_PRINT_INFO(ssl, w, flag, msg)                                      \
  do {                                                                         \
    if (w & flag) {                                                            \
      fprintf(stderr, "%s - %s - %s\n", msg, SSL_state_string(ssl),            \
              SSL_state_string_long(ssl));                                     \
    }                                                                          \
  } while (0);

static void ssl_info_callback(const SSL *ssl, int where, int ret) {
  if (ret == 0) {
    fprintf(stderr, "ssl_info_callback, error occurred.\n");
    return;
  }
  SSL_PRINT_INFO(ssl, where, SSL_CB_LOOP, "LOOP");
  SSL_PRINT_INFO(ssl, where, SSL_CB_EXIT, "EXIT");
  SSL_PRINT_INFO(ssl, where, SSL_CB_READ, "READ");
  SSL_PRINT_INFO(ssl, where, SSL_CB_WRITE, "WRITE");
  SSL_PRINT_INFO(ssl, where, SSL_CB_ALERT, "ALERT");
  SSL_PRINT_INFO(ssl, where, SSL_CB_HANDSHAKE_DONE, "HANDSHAKE DONE");
}
#undef SSL_PRINT_INFO
#endif

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
    bytes = rb->ret;
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
    BIO_set_shutdown(bio, num);
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

struct uvtls_session_s {
  SSL *ssl;
  BIO *incoming_bio;
  BIO *outgoing_bio;
};

typedef struct uvtls_session_s uvtls_session_t;

static uvtls_session_t *uvtls_session_create(SSL_CTX *ssl_ctx,
                                             uvtls_ringbuffer_t *incoming,
                                             uvtls_ringbuffer_t *outgoing) {
  uvtls_session_t *session = (uvtls_session_t *)malloc(sizeof(uvtls_session_t));

  if (ssl_ctx) {
    SSL_CTX_up_ref(ssl_ctx);
  } else {
    ssl_ctx = SSL_CTX_new(SSL_CLIENT_METHOD());
  }

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

  int rc = SSL_connect(session->ssl);
  if (rc <= 0) {
    int err = SSL_get_error(session->ssl, rc);
    if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_NONE) {
      ssl_print_error();
      return -1;
    }
  }

  char data[SSL_HANDSHAKE_MAX_BUFFER_SIZE];
  int size =
      BIO_read(session->outgoing_bio, data, SSL_HANDSHAKE_MAX_BUFFER_SIZE);
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

static void on_handshake_read(uv_stream_t *stream, ssize_t nread,
                              const uv_buf_t *buf) {

  uvtls_t *tls = (uvtls_t *)stream->data;
  uvtls_session_t *session = (uvtls_session_t *)tls->impl;

  if ((nread == UV_EOF && !SSL_is_init_finished(session->ssl)) ||
      (nread != UV_EOF && nread < 0)) {
    uv_read_stop(stream);
    tls->connect_req->cb(tls->connect_req, -1);
    tls->connect_req = NULL;
    return;
  }

  uvtls_ringbuffer_tail_block_commit(&tls->incoming, (int)nread);

  int rc = do_handshake(tls);
  if (rc != 0 || SSL_is_init_finished(session->ssl)) {
    uv_read_stop(stream);
    tls->connect_req->cb(tls->connect_req, -1);
    tls->connect_req = NULL;
  }
}

static void on_read(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
  uvtls_t *tls = (uvtls_t *)stream->data;
  uvtls_session_t *session = (uvtls_session_t *)tls->impl;

  if (nread < 0) {
    tls->read_cb(tls, nread, NULL);
    return;
  }

  uvtls_ringbuffer_tail_block_commit(&tls->incoming, (int)nread);

  char data[SSL_HANDSHAKE_MAX_BUFFER_SIZE];
  ssize_t num_bytes;
  uv_buf_t temp = uv_buf_init(data, SSL_HANDSHAKE_MAX_BUFFER_SIZE);
  while ((num_bytes = SSL_read(session->ssl, data,
                               SSL_HANDSHAKE_MAX_BUFFER_SIZE)) > 0) {
    tls->read_cb(tls, num_bytes, &temp);
  }
}

static void on_write(uv_write_t *req, int status) {
  uvtls_write_t *write_req = (uvtls_write_t *)req->data;
  uvtls_ringbuffer_head_blocks_commit(&write_req->tls->outgoing,
                                      write_req->to_commit);
  write_req->cb(write_req, status);
}

int uvtls_lib_init() {
  SSL_library_init();
  SSL_load_error_strings();
  OpenSSL_add_all_algorithms();
  return 0;
}

void uvtls_lib_cleanup() {
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

int uvtls_init(uvtls_t *tls, uv_stream_t *stream) {
  ringbuffer_bio_init_once();
  tls->stream = stream;
  tls->read_cb = NULL;
  tls->connect_req = NULL;
  /* FIXME: OOM */
  uvtls_ringbuffer_init(&tls->incoming);
  uvtls_ringbuffer_init(&tls->outgoing);
  tls->impl = uvtls_session_create(NULL, &tls->incoming, &tls->outgoing);
  if (!tls->impl)
    return UV_ENOMEM;
  return 0;
}

int uvtls_init_copy(uvtls_t *orig, uvtls_t *copy) { return -1; }

void uvtls_close(uvtls_t *tls) {
  uvtls_read_stop(tls);

  uvtls_session_t *session = (uvtls_session_t *)tls->impl;
  SSL_CTX_free(SSL_get_SSL_CTX(session->ssl));
  SSL_free(session->ssl);
  free(session);
}

int uvtls_connect(uvtls_connect_t *req, uvtls_t *tls, uvtls_connect_cb cb) {
  uvtls_session_t *session = (uvtls_session_t *)tls->impl;

  req->tls = tls;
  req->cb = cb;
  tls->stream->data = tls;
  tls->connect_req = req;

  int rc = do_handshake(tls);
  assert(!SSL_is_init_finished(session->ssl) &&
         "Handshake shouldn't be finished");
  if (rc != 0) {
    return -1;
  }

  return uv_read_start(tls->stream, on_alloc, on_handshake_read);
}

int uvtls_read_start(uvtls_t *tls, uvtls_read_cb read_cb) {
  tls->stream->data = tls;
  tls->read_cb = read_cb;
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
