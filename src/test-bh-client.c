#include <uvtls.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void on_write(uvtls_write_t* req, int status);

void on_close(uvtls_t* tls) {
  printf("client close\n");
}

typedef struct request_s request_t;

struct request_s {
  uvtls_t* tls;
  uvtls_connect_t connect_req;
  uvtls_write_t write_req;
  size_t length;
  char data[64 * 1024 + 5];
};

void on_connect(uvtls_connect_t* req, int status) {
  uv_buf_t buf;
  request_t* request = (request_t*) req->data;

  if (status != 0) {
    fprintf(stderr, "Failed to connect \"%s\"\n", uvtls_strerror(status));
    uvtls_close(req->tls, on_close);
    return;
  }

  request->data[0] = 1;
  request->data[1] = (char) ((request->length >> 24) & 0xff);
  request->data[2] = (char) ((request->length >> 16) & 0xff);
  request->data[3] = (char) ((request->length >> 8) & 0xff);
  request->data[4] = (char) ((request->length) & 0xff);
  request->data[5] = 'a';

  buf.base = request->data;
  buf.len = 64 * 1024;

  if (buf.len > request->length) {
    buf.len = request->length;
  }

  request->length -= buf.len;
  uvtls_write(&request->write_req, req->tls, &buf, 1, on_write);
}

void on_tcp_connect(uv_connect_t* req, int status) {
  request_t* request = (request_t*) req->data;
  uvtls_connect(&request->connect_req, request->tls, on_connect);
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
  uv_buf_t buf;
  request_t* request = (request_t*) req->data;

  if (request->length == 0) {
    uvtls_close(req->tls, on_close);
    return;
  }

  buf.base = request->data;
  buf.len = 64 * 1024;

  if (buf.len > request->length) {
    buf.len = request->length;
  }

  request->length -= buf.len;
  uvtls_write(&request->write_req, req->tls, &buf, 1, on_write);
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

int main() {
  struct sockaddr_in addr;
  uv_loop_t loop;
  uv_tcp_t client;
  uvtls_t tls_client;
  uvtls_context_t tls_context_client;
  uv_connect_t connect_req;
  request_t request;

  uv_loop_init(&loop);

  uv_ip4_addr("127.0.0.1", 8888, &addr);

  uv_tcp_init(&loop, &client);
  uvtls_context_init(&tls_context_client, UVTLS_CONTEXT_LIB_INIT);
  uvtls_context_set_verify_flags(&tls_context_client, UVTLS_VERIFY_PEER_CERT);

  uvtls_context_add_trusted_certs(&tls_context_client, cert, strlen(cert));

  uvtls_init(&tls_client, &tls_context_client, (uv_stream_t*) &client);

  request.tls = &tls_client;
  request.length = 1024 * 1024 * 1024;
  request.write_req.data = &request;
  request.connect_req.data = &request;

  connect_req.data = &request;
  uv_tcp_connect(
      &connect_req, &client, (const struct sockaddr*) &addr, on_tcp_connect);

  uv_run(&loop, UV_RUN_DEFAULT);

  uvtls_context_destroy(&tls_context_client);

  uv_loop_close(&loop);
}
