#include <uvtls.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct http_client_s http_client_t;

struct http_client_s {
  uv_tcp_t tcp;
  uvtls_t tls;
  uv_connect_t connect_req;
  uvtls_write_t write_req;
  char read_buf[64 * 1024];
  char write_buf[1024];
};

void on_write(uvtls_write_t* req, int status);

void on_close(uvtls_t* tls) {
  /* Do close stuff */
}

void on_connect(uvtls_t* tls, int status) {
  http_client_t* client = (http_client_t*) tls->data;
  uv_buf_t buf;

  if (status != 0) {
    fprintf(stderr,
            "Failed to establish TLS connection (%s)\n",
            uvtls_strerror(status));
    uvtls_close(tls, on_close);
    return;
  }

  sprintf(client->write_buf,
          "GET / HTTP/1.0\r\n"
          "Host: %s\r\n\r\n",
          tls->hostname);

  buf.base = client->write_buf;
  buf.len = strlen(buf.base);
  uvtls_write(&client->write_req, tls, &buf, 1, on_write);
}

void on_tcp_connect(uv_connect_t* req, int status) {
  uvtls_t* tls = (uvtls_t*) req->data;

  if (status != 0) {
    fprintf(stderr, "Failed to connect (%s)", uv_strerror(status));
    uvtls_close(tls, on_close);
    return;
  }

  uvtls_connect(tls, on_connect);
}

void on_alloc(uvtls_t* tls, size_t suggested_size, uv_buf_t* buf) {
  static char data[64 * 1024];
  buf->base = data;
  buf->len = sizeof(data);
}

void on_read(uvtls_t* tls, ssize_t nread, const uv_buf_t* buf) {
  if (nread > 0) {
    printf("%.*s", (int) nread, buf->base);
  } else if (!uvtls_is_closing(tls)) {
    if (nread != UV_EOF) {
      fprintf(stderr, "Read error (%s)", uv_strerror((int) nread));
    }
    uvtls_close(tls, on_close);
  }
}

void on_write(uvtls_write_t* req, int status) {
  uvtls_read_start(req->tls, on_alloc, on_read);
}

void on_getaddrinfo(uv_getaddrinfo_t* req, int status, struct addrinfo* res) {
  http_client_t* client = (http_client_t*) req->data;

  if (status != 0 || !res) {
    fprintf(stderr,
            "Unable to resolve \"%s\" (%s)\n",
            client->tls.hostname,
            uv_strerror(status));
    uvtls_close(&client->tls, on_close);
    return;
  }

  uv_tcp_connect(
      &client->connect_req, &client->tcp, res->ai_addr, on_tcp_connect);
  uv_freeaddrinfo(res);
}

int main(int argc, char** argv) {
  uvtls_context_t tls_context;
  uv_getaddrinfo_t getaddrinfo_req;
  http_client_t client;
  struct addrinfo hints;
  char* host;

  if (argc <= 1) {
    fprintf(stderr, "Usage: %s <host>\n", argv[0]);
    return 1;
  }

  host = argv[1];

  client.connect_req.data = &client.tls;
  client.tls.data = &client;

  uvtls_context_init(&tls_context, UVTLS_CONTEXT_LIB_INIT);
  uvtls_context_set_verify_flags(&tls_context, UVTLS_VERIFY_PEER_IDENT);

  uv_tcp_init(uv_default_loop(), &client.tcp);

  uvtls_init(&client.tls, &tls_context, (uv_stream_t*) &client.tcp);
  uvtls_set_hostname(&client.tls, host, strlen(host));

  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags = 0;
  hints.ai_protocol = 0;

  getaddrinfo_req.data = &client;
  uv_getaddrinfo(
      uv_default_loop(), &getaddrinfo_req, on_getaddrinfo, host, "443", NULL);

  uv_run(uv_default_loop(), UV_RUN_DEFAULT);

  uv_loop_close(uv_default_loop());

  uvtls_context_destroy(&tls_context);
}
