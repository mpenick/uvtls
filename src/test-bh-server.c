#include <uvtls.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char write_data[64 * 1024];

static const char *cert =
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

static const char *key =
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

typedef struct client_s client_t;
typedef struct request_s request_t;

typedef enum { OPCODE, LENGTH, BODY } client_state_t;
typedef enum { UNKNOWN, READ, WRITE } client_opcode_t;

struct client_s {
  uv_tcp_t tcp;
  uvtls_t tls;
  uvtls_write_t req;
  client_state_t state;
  client_opcode_t opcode;
  size_t length, total;
  uint64_t start;
  char temp[64];
  size_t temp_size;
  char data[64 * 1024];
};

void do_write(client_t *client);

void on_server_client_close(uvtls_t *tls) {
  client_t *client = (client_t *)tls->data;
  printf("server client close\n");
  if (client->start > 0) {
    uint64_t delta = uv_hrtime() - client->start;
    double elapsed = (double)delta / (1e9);
    printf("%f MB/sec (%lu bytes in %f secs)\n",
           (client->total / elapsed) / (1024 * 1024), client->total, elapsed);
  }
  free(client);
}

void on_server_client_write(uvtls_write_t *req, int status) {
  client_t *client = (client_t *)req->tls->data;

  if (status != 0) {
    fprintf(stderr, "Write error %s\n", uvtls_strerror(status));
    uvtls_close(req->tls, on_server_client_close);
    return;
  }

  do_write(client);
}

void do_write(client_t *client) {
  if (client->length != 0) {
    uv_buf_t buf;
    buf.base = write_data;
    buf.len = 64 * 1024;
    if (buf.len > client->length) {
      buf.len = client->length;
    }
    client->length -= buf.len;
    uvtls_write(&client->req, &client->tls, &buf, 1, on_server_client_write);
  }
}

void on_server_client_read(uvtls_t *tls, ssize_t nread, const uv_buf_t *buf) {
  client_t *client = (client_t *)tls->data;
  const char *pos = buf->base;
  const char *end = buf->base + nread;

  if (nread < 0) {
    if (nread != UV_EOF && nread != UV_ECONNRESET) {
      fprintf(stderr, "Read error: %s\n", uvtls_strerror((int)nread));
    }
    uvtls_close(tls, on_server_client_close);
    return;
  }

  while (pos != end) {
    size_t nbytes;
    switch (client->state) {
    case OPCODE:
      switch (*pos++) {
      case READ:
        client->opcode = READ;
        break;
      case WRITE:
        client->opcode = WRITE;
        break;
      default:
        fprintf(stderr, "Invalid opcode %d\n", (int)*pos);
        uvtls_close(tls, on_server_client_close);
        return;
      }
      client->start = uv_hrtime();
      client->state = LENGTH;
      break;
    case LENGTH:
      nbytes = (size_t)(end - pos);
      if (nbytes > 4 - client->temp_size) {
        nbytes = 4 - client->temp_size;
      }
      memcpy(client->temp, pos, nbytes);
      client->temp_size += nbytes;
      if (client->temp_size == 4) {
        client->state = BODY;
        client->total = client->length =
            (size_t)((uint8_t)client->temp[0] << 24) |
            (size_t)((uint8_t)client->temp[1] << 16) |
            (size_t)((uint8_t)client->temp[2] << 8) |
            (size_t)(uint8_t)client->temp[3];
      }
      pos += nbytes;
      break;
    case BODY:
      if (client->opcode == READ) {
        nbytes = (size_t)(end - pos);
        if (nbytes >= client->length) {
          client->state = OPCODE;
          nbytes = client->length;
        }
        pos += nbytes;
      } else {
        do_write(client);
      }
      break;
    }
  }

  if (client->state == BODY && client->opcode == WRITE) {
    do_write(client);
  }
}

void on_server_client_alloc(uvtls_t *tls, size_t suggested_size,
                            uv_buf_t *buf) {
  client_t *client = (client_t *)tls->data;
  buf->base = client->data;
  buf->len = sizeof(client->data);
}

void on_accept(uvtls_t *client, int status) {
  if (status != 0) {
    fprintf(stderr, "Unable to accept client: %s\n", uvtls_strerror(status));
    uvtls_close(client, on_server_client_close);
    return;
  }
  printf("accept\n");
  uvtls_read_start(client, on_server_client_alloc, on_server_client_read);
}

static int client_init(uvtls_t *server, client_t *client) {
  int rc;
  client->tls.data = client;
  client->start = 0;
  client->state = OPCODE;
  client->opcode = UNKNOWN;
  client->temp_size = client->length = 0;

  rc = uv_tcp_init(server->stream->loop, &client->tcp);
  if (rc != 0) {
    return rc;
  }

  rc = uvtls_init(&client->tls, server->context, (uv_stream_t *)&client->tcp);
  if (rc != 0) {
    uv_close((uv_handle_t *)&client->tcp, NULL);
  }

  return rc;
}

void on_connection(uvtls_t *server, int status) {
  client_t *client = (client_t *)malloc(sizeof(client_t));

  int rc = client_init(server, client);
  if (rc != 0) {
    fprintf(stderr, "Unable to initialize client: %s\n", uvtls_strerror(rc));
    uvtls_close(server, NULL);
    return;
  }

  uvtls_accept(server, &client->tls, on_accept);
}

int main() {
  struct sockaddr_in bindaddr;
  uv_loop_t loop;
  uv_tcp_t server;
  uvtls_t tls_server;
  uvtls_context_t tls_context_server;

  uv_loop_init(&loop);

  /* Server */
  uv_ip4_addr("0.0.0.0", 8888, &bindaddr);

  uv_tcp_init(&loop, &server);
  uv_tcp_bind(&server, (const struct sockaddr *)&bindaddr, 0);

  uvtls_context_init(&tls_context_server, UVTLS_CONTEXT_LIB_INIT);
  uvtls_context_set_verify_flags(&tls_context_server, UVTLS_VERIFY_NONE);
  uvtls_context_set_cert(&tls_context_server, cert, strlen(cert));
  uvtls_context_set_private_key(&tls_context_server, key, strlen(key));

  uvtls_init(&tls_server, &tls_context_server, (uv_stream_t *)&server);

  uvtls_listen(&tls_server, 100, on_connection);

  uv_run(&loop, UV_RUN_DEFAULT);

  /* Cleanup */
  uvtls_context_destroy(&tls_context_server);

  uv_loop_close(&loop);
}
