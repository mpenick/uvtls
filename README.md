# uvtls

TLS/SSL extension for [libuv] that tries to conform to its style and idioms.
If you're used to using libuv then it should be easy for you to pick up uvtls
and integrate it into your application.

## Working features

* Client-side support
* Server-side support
* OpenSSL integration

## Work in progress

This is a work in-progress and is currently pre-alpha quality software. I'm
currently working on the following:

* Tests
* Documentation
* API refinement
* Support for other TLS/SSL libraries

## Contributing

Please feel free to contribute issues and PRs! Please run `clang-format` on your
code before submitting.

## Client example

```c
#include <uvtls.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void on_write(uvtls_write_t* req, int status);

void on_close(uvtls_t* tls) {
  printf("client close\n");
}

void on_connect(uvtls_connect_t* req, int status) {
  uvtls_write_t* write_req;
  uv_buf_t buf;

  if (status != 0) {
    fprintf(stderr, "Failed to connect \"%s\"\n", uvtls_strerror(status));
    uvtls_close(req->tls, on_close);
    free(req);
    return;
  }

  write_req = (uvtls_write_t*) malloc(sizeof(uvtls_write_t));

  buf.base =
      "GET / HTTP/1.0\r\n"
      "Host: www.google.com\r\n\r\n";
  buf.len = strlen(buf.base);
  uvtls_write(write_req, req->tls, &buf, 1, on_write);

  free(req);
}

void on_tcp_connect(uv_connect_t* req, int status) {
  uvtls_t* tls = (uvtls_t*) req->data;
  uvtls_connect_t* connect_req =
      (uvtls_connect_t*) malloc(sizeof(uvtls_connect_t));
  uvtls_connect(connect_req, tls, on_connect);
}

void on_alloc(uvtls_t* tls, size_t suggested_size, uv_buf_t* buf) {
  static char data[64 * 1024];
  buf->base = data;
  buf->len = sizeof(data);
}

void on_read(uvtls_t* tls, ssize_t nread, const uv_buf_t* buf) {
  if (nread > 0) {
    printf("client: %.*s\n", (int) nread, buf->base);
  } else {
    uvtls_close(tls, on_close);
  }
}

void on_write(uvtls_write_t* req, int status) {
  uvtls_read_start(req->tls, on_alloc, on_read);
  free(req);
}

int main() {
  uv_loop_t loop;
  uv_tcp_t tcp;
  uvtls_t tls;
  uvtls_context_t tls_context;
  uv_connect_t connect_req;

  struct sockaddr_in addr;
  uv_ip4_addr("172.217.164.174", 443, &addr);

  uv_loop_init(&loop);
  uv_tcp_init(&loop, &tcp);

  uvtls_context_init(&tls_context, UVTLS_CONTEXT_LIB_INIT);
  uvtls_context_set_verify_flags(&tls_context, UVTLS_VERIFY_NONE);

  uvtls_init(&tls, &tls_context, (uv_stream_t*) &tcp);

  uvtls_set_hostname(&tls, "google.com", strlen("google.com"));

  connect_req.data = &tls;
  uv_tcp_connect(
      &connect_req, &tcp, (const struct sockaddr*) &addr, on_tcp_connect);

  uv_run(&loop, UV_RUN_DEFAULT);

  uv_loop_close(&loop);

  uvtls_context_destroy(&tls_context);
}
```

[libuv]: https://github.com/libuv/libuv
