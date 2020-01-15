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

## Client/Server example

```c
#include <uvtls.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void on_server_client_close(uvtls_t* tls) {
  printf("server client close\n");
  free(tls->stream);
  free(tls);
}

void on_server_client_write(uvtls_write_t* req, int status) {
  uvtls_close(req->tls, on_server_client_close);
  free(req);
}

void on_server_client_read(uvtls_t* tls, ssize_t nread, const uv_buf_t* buf) {
  if (nread < 0) {
    uvtls_close(tls, on_server_client_close);
    return;
  }

  printf("server: %.*s\n", (int) nread, buf->base);

  {
    uvtls_write_t* write_req = (uvtls_write_t*) malloc(sizeof(uvtls_write_t));
    uv_buf_t buf;
    buf.base = "<html><head>Hi</head><body>Bye</body></html>";
    buf.len = strlen(buf.base);
    uvtls_write(write_req, tls, &buf, 1, on_server_client_write);
  }
}

void on_server_client_alloc(uvtls_t* tls,
                            size_t suggested_size,
                            uv_buf_t* buf) {
  static char data[64 * 1024];
  buf->base = data;
  buf->len = sizeof(data);
}

void on_accept(uvtls_t* client, int status) {
  printf("accept\n");
  uvtls_read_start(client, on_server_client_alloc, on_server_client_read);
}

void on_connection(uvtls_t* server, int status) {
  uv_tcp_t* tcp = (uv_tcp_t*) malloc(sizeof(uv_tcp_t));
  uvtls_t* client = (uvtls_t*) malloc(sizeof(uvtls_t));

  uv_tcp_init(server->stream->loop, tcp);
  uvtls_init(client, server->context, (uv_stream_t*) tcp);

  uvtls_accept(server, client, on_accept);
  uvtls_close(server, NULL);
}

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


static const char* cert;
static const char* key;

int main() {
  struct sockaddr_in addr;
  struct sockaddr_in bindaddr;
  uv_loop_t loop;
  uv_tcp_t client, server;
  uvtls_t tls_client, tls_server;
  uvtls_context_t tls_context_client, tls_context_server;
  uv_connect_t connect_req;

  uv_loop_init(&loop);

  uv_ip4_addr("127.0.0.1", 8888, &addr);

  /* Server */
  uv_ip4_addr("0.0.0.0", 8888, &bindaddr);

  uv_tcp_init(&loop, &server);
  uv_tcp_bind(&server, (const struct sockaddr*) &bindaddr, 0);

  uvtls_context_init(&tls_context_server, UVTLS_CONTEXT_LIB_INIT);
  uvtls_context_set_verify_flags(&tls_context_server, UVTLS_VERIFY_NONE);
  uvtls_context_set_cert(&tls_context_server, cert, strlen(cert));
  uvtls_context_set_private_key(&tls_context_server, key, strlen(key));

  uvtls_init(&tls_server, &tls_context_server, (uv_stream_t*) &server);

  uvtls_listen(&tls_server, 100, on_connection);

  /* Client */
  uv_tcp_init(&loop, &client);
  uvtls_context_init(&tls_context_client, UVTLS_CONTEXT_LIB_INIT);
  uvtls_context_set_verify_flags(&tls_context_client, UVTLS_VERIFY_PEER_CERT);

  uvtls_context_add_trusted_certs(&tls_context_client, cert, strlen(cert));

  uvtls_init(&tls_client, &tls_context_client, (uv_stream_t*) &client);

  connect_req.data = &tls_client;
  uv_tcp_connect(
      &connect_req, &client, (const struct sockaddr*) &addr, on_tcp_connect);

  uv_run(&loop, UV_RUN_DEFAULT);

  /* Cleanup */
  uvtls_context_destroy(&tls_context_client);
  uvtls_context_destroy(&tls_context_server);

  uv_loop_close(&loop);
}

static const char* cert =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIDazCCAlOgAwIBAgIUNgd/YyO3R5N9POwL/k0w3owRZ8YwDQYJKoZIhvcNAQEL\n"
    "BQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM\n"
    "GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0xOTEyMTgyMDUzMDNaFw0yMDEy\n"
    "MTcyMDUzMDNaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw\n"
    "HwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggEiMA0GCSqGSIb3DQEB\n"
    "AQUAA4IBDwAwggEKAoIBAQCf128XN+VmcSJaQEvKfd69PzbbW0ogHAWZnfPukmXs\n"
    "d2sapO+0fG1poP8UJpEC1J7T8c76T6OUGbThfs6mJhg8rg/YgmY5GXhj6mYXak1z\n"
    "oajSrytN5pB8h5W+xvIjPHsxaxOFsw8tC5Cz4d366suIluRzW3oyFnXNur9UVYAW\n"
    "DqCqhU+sLfH+mh2d5gE6RvBkmWsXkyUeC8mQriU4IzwZuse9cFB5phG1SSLWeIyH\n"
    "2bMxQ8GbofSJULY12rppq9fWclAicMMvx1lJdE5DYVfSPApX+1tKzczH6Aqbh0pN\n"
    "igshe99f8GBZ/ILLhhS2KGmNCrJjW+j4f7mJpB1Hl/vZAgMBAAGjUzBRMB0GA1Ud\n"
    "DgQWBBT1DTP5FtJwlQa7rUHzKaeAz0+dNDAfBgNVHSMEGDAWgBT1DTP5FtJwlQa7\n"
    "rUHzKaeAz0+dNDAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAg\n"
    "ETZZEcGS9/Sietf+lguBGwE9pqPHpMWF2Wic3gLsFwryXyEQBMwTNzrXHH/NtCzR\n"
    "oU+5rko6fnrUgLy7sYojH4fYUpl7XIlVkc7TyR1XOShs2g7r7P9G/BOGj0b+GmOr\n"
    "+VCr+geMCwEqcdrw/ChoiWGdf1lpFQGNVfZd2B1kTMldOQ4DKnoiwUva5QtRMj8H\n"
    "DnonvhK3XM7BveVhrWojC/ccNo4JeGnIhKgtZEtelLP9WEtNTTc+ZuqSuA4p0550\n"
    "4aSSKzG+5HtavoFaxtXiLLOE3cwWnKwcJA82qEm7C1PWM928kIP6fozZlvGf7h8I\n"
    "GfMmS973Gk5+TU3g4Em9\n"
    "-----END CERTIFICATE-----";

static const char* key =
    "-----BEGIN PRIVATE KEY-----\n"
    "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCf128XN+VmcSJa\n"
    "QEvKfd69PzbbW0ogHAWZnfPukmXsd2sapO+0fG1poP8UJpEC1J7T8c76T6OUGbTh\n"
    "fs6mJhg8rg/YgmY5GXhj6mYXak1zoajSrytN5pB8h5W+xvIjPHsxaxOFsw8tC5Cz\n"
    "4d366suIluRzW3oyFnXNur9UVYAWDqCqhU+sLfH+mh2d5gE6RvBkmWsXkyUeC8mQ\n"
    "riU4IzwZuse9cFB5phG1SSLWeIyH2bMxQ8GbofSJULY12rppq9fWclAicMMvx1lJ\n"
    "dE5DYVfSPApX+1tKzczH6Aqbh0pNigshe99f8GBZ/ILLhhS2KGmNCrJjW+j4f7mJ\n"
    "pB1Hl/vZAgMBAAECggEARF3Bzz2CKenT1qRPhoGFxo4GKZaHQuqZXpYXooANhjGh\n"
    "ptjLCfh6V8abs4O3XG2SrXZsn9V2Ur8YBabWPmxmy3Vro6BKlruVKa81EWjPTdjk\n"
    "O5DexcgLHqhjXSD8qiORUZbJ19K5d/vNXZMK/ep1OavIdKq4vjmrE15/vVOAoG3e\n"
    "MOQU24UHOgA6m81k2ZpvDA5T+Ahz8nPQyM1MKNu/6dFD8ncgqE9RkVGp33UvxKGK\n"
    "BvrPI01CeKxEfkYJsmdf4Mw3Pt44MdcVSDQZgveQ/tqQI86vP5KB77jVj7VEN+2m\n"
    "JE6vPILV4mK4q29fZc3Gqohsl9rwNvBUXE2VEuKIgQKBgQDLV54jZId6Aa0UaiYB\n"
    "V5W0/6ZAy949kPR8f+kDSvUGh8KGZxXEmfkZ1QgS/TGcNjU07qxk9mGOBy992koa\n"
    "TirhLiIo+5Ms8sSJNTxdlx19KEPzGgncKBofQGbnOQjL1m46N+tMrR3rP4P0eS77\n"
    "EuKY1GPWUo2XKmMtaaUq43LiMQKBgQDJO/oy4vHMQ8O0Z4FXzB9po1m5yUArf+fP\n"
    "ACXP52Qj5KWYzdiKZjzda/b8BTuC+WYvAFyxKwY+w2K3+5yI5/6SnaUrVXc5+pFW\n"
    "Wulfq/QuMC3IQjNoOnCqjx+NX9s4LYlV1wIynHI7MM3YnXc/upZHlx2TNhAMGum2\n"
    "NkfCP4tiKQKBgCyqpnYn0wqd66McXhTVZHFJ5v88ySjE+q+OeWTbxk8U60oSwtlY\n"
    "6TsfbJKfQ5KI5c8mzn+vD2bfdTM0DCsTGKA2PhK6kG3DNiDdrNDyLOwdOC/ifF/7\n"
    "/yD2SKRqBuCfzb7EIc/KB1Rxs060f/lvAI+JuBSQNcIK8ZY8KqftJoNBAoGBALd9\n"
    "VwB7axtkVtjy4D+cQrBiYHhFh5uif06Cxfey9966qDySxfY8jxcfURAv/TnKC2Ck\n"
    "JeDuaD1mj2dPqEY1tC0gTfEbdyGI1mk1cELqWjabe8N0icdqMj1zT8PrOcsZynZZ\n"
    "HQnlGUvbjncL7iZQDqOsqS0ISM2g5KZfDEOVCZUxAoGBAK8PYF6cgmyOXqv0clWT\n"
    "AYGk1pUNv38PkwcmOHZKaDS27If+lhHQz+ncm+gLIezcNfNPURRBOSHLi8egSfYb\n"
    "1JPBzAPTg25NrBo8UxLHeq7RAU8PfmIZC7rPZvyZZ0ODjHKoiE+Hn6dtQ3IjmUva\n"
    "UI1Sl95I+hqh9u6RfI0n2IJm\n"
    "-----END PRIVATE KEY-----\n";
```

[libuv]: https://github.com/libuv/libuv
