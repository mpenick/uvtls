#ifndef UVTLS_H
#define UVTLS_H

#include <uv.h>
#include <uvtls/ringbuffer.h>

typedef struct uvtls_s uvtls_t;
typedef struct uvtls_write_s uvtls_write_t;
typedef struct uvtls_connect_s uvtls_connect_t;

typedef void (*uvtls_read_cb)(uvtls_t *tls, ssize_t nread, const uv_buf_t *buf);
typedef void (*uvtls_connect_cb)(uvtls_connect_t *req, int status);
typedef void (*uvtls_write_cb)(uvtls_write_t *req, int status);

struct uvtls_s {
  uv_stream_t *stream;
  void *data;
  void *impl;
  uvtls_ringbuffer_t incoming;
  uvtls_ringbuffer_t outgoing;
  uvtls_read_cb read_cb;
  uvtls_connect_t *connect_req;
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
  int to_commit;
  uvtls_write_cb cb;
};

int uvtls_lib_init(void);
void uvtls_lib_cleanup(void);

int uvtls_init(uvtls_t *tls, uv_stream_t *stream);
int uvtls_init_copy(uvtls_t *orig, uvtls_t *copy);

void uvtls_close(uvtls_t *tls);

int uvtls_connect(uvtls_connect_t *req, uvtls_t *tls, uvtls_connect_cb cb);

int uvtls_read_start(uvtls_t *tls, uvtls_read_cb read_cb);
int uvtls_read_stop(uvtls_t *tls);

int uvtls_write(uvtls_write_t *req, uvtls_t *tls, const uv_buf_t bufs[],
                unsigned int nbufs, uvtls_write_cb cb);

#endif /* UVTLS_H */
