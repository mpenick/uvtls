#ifndef UVTLS_H
#define UVTLS_H

#include <uv.h>
#include <uvtls/ring_buf.h>

/*
 * TODO:
 * - Error handling
 * - Verify flags
 * - Client-side certificates (done-ish)
 * - Trusted certificates
 */

typedef struct uvtls_context_s uvtls_context_t;
typedef struct uvtls_s uvtls_t;
typedef struct uvtls_write_s uvtls_write_t;
typedef struct uvtls_connect_s uvtls_connect_t;

typedef void (*uvtls_read_cb)(uvtls_t *tls, ssize_t nread, const uv_buf_t *buf);
typedef void (*uvtls_connection_cb)(uvtls_t *server, int status);
typedef void (*uvtls_accept_cb)(uvtls_t *client, int status);
typedef void (*uvtls_connect_cb)(uvtls_connect_t *req, int status);
typedef void (*uvtls_write_cb)(uvtls_write_t *req, int status);

#define UVTLS__ERR(x) (UV_ERRNO_MAX - (x))

#define UVTLS__UNKNOWN UVTLS__ERR(100) /* FIXME */
#define UVTLS__EINVAL UVTLS__ERR(5)
#define UVTLS__EHANDSHAKE UVTLS__ERR(2)
#define UVTLS__ENOPEERCERT UVTLS__ERR(3)
#define UVTLS__EBADPEERCERT UVTLS__ERR(2)
#define UVTLS__EBADPEERIDNT UVTLS__ERR(1)

#define UVTLS_ERRNO_MAP(XX)                                                    \
  XX(UNKNOWN, "unknown tls error")                                             \
  XX(EINVAL, "invalid argument")                                               \
  XX(EHANDSHAKE, "handshake error")                                            \
  XX(ENOPEERCERT, "no peer certificate")                                       \
  XX(EBADPEERCERT, "invalid peer certificate")                                 \
  XX(EBADPEERIDNT, "invalid peer identity")

typedef enum {
#define XX(code, _) UVTLS_##code = UVTLS__##code,
  UVTLS_ERRNO_MAP(XX)
#undef XX
      UVTLS_ERRNO_MAX = UVTLS__UNKNOWN - 1
} uvtls_errno_t;

struct uvtls_context_s {
  void *data;
  void *impl;
  int verify_flags;
};

struct uvtls_s {
  uv_stream_t *stream;
  void *data;
  void *impl;
  uvtls_context_t *context;
  char hostname[256];
  uvtls_ring_buf_t incoming;
  uvtls_ring_buf_t outgoing;
  uvtls_read_cb read_cb;
  uvtls_connect_t *connect_req;
  uvtls_connection_cb connection_cb;
  uvtls_accept_cb accept_cb;
  uvtls_ring_buf_pos_t commit_pos;
};

struct uvtls_connect_s {
  void *data;
  uvtls_t *tls;
  uvtls_connect_cb cb;
};

struct uvtls_write_s {
  uv_write_t req;
  void *data;
  uvtls_t *tls;
  uvtls_write_cb cb;
  uvtls_ring_buf_pos_t commit_pos;
};

typedef enum {
  UVTLS_CONTEXT_LIB_INIT = 0x01,
  UVTLS_CONTEXT_DEBUG = 0x02,
} uvtls_context_flags_t;

typedef enum {
  UVTLS_VERIFY_NONE = 0x00,
  UVTLS_VERIFY_PEER_CERT = 0x01,
  UVTLS_VERIFY_PEER_IDENTITY = 0x02
} uvtls_verify_flags_t;

int uvtls_context_init(uvtls_context_t *context, int init_flags);
void uvtls_context_close(uvtls_context_t *context);

void uvtls_context_set_verify_flags(uvtls_context_t *context, int verify_flags);

int uvtls_context_add_trusted_cert(uvtls_context_t *context, const char *cert,
                                   size_t length);
int uvtls_context_set_cert(uvtls_context_t *context, const char *cert,
                           size_t length);
int uvtls_context_set_private_key(uvtls_context_t *context, const char *key,
                                  size_t length);

int uvtls_init(uvtls_t *tls, uvtls_context_t *context, uv_stream_t *stream);
void uvtls_close(uvtls_t *tls);

int uvtls_set_hostname(uvtls_t *tls, const char *hostname, size_t length);

int uvtls_connect(uvtls_connect_t *req, uvtls_t *tls, uvtls_connect_cb cb);

int uvtls_listen(uvtls_t *tls, int backlog, uvtls_connection_cb cb);
int uvtls_accept(uvtls_t *server, uvtls_t *client, uvtls_accept_cb cb);

int uvtls_read_start(uvtls_t *tls, uvtls_read_cb read_cb);
int uvtls_read_stop(uvtls_t *tls);

int uvtls_write(uvtls_write_t *req, uvtls_t *tls, const uv_buf_t bufs[],
                unsigned int nbufs, uvtls_write_cb cb);

#endif /* UVTLS_H */
