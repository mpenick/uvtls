/* Copyright Michael A. Penick
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include "server.h"

#include <stdlib.h>
#include <string.h>

#include "certs.h"
#include "test.h"

static void on_client_close(uvtls_t* tls) {
  int i;
  client_t* client = (client_t*) tls->data;

  for (i = 0; i < MAX_SERVER_CLIENTS; ++i) {
    if (client->server->clients[i] == client) {
      client->server->clients[i] = NULL;
      break;
    }
  }
  if (i == MAX_SERVER_CLIENTS) abort();
  free(client);
}

static void on_client_write(uvtls_write_t* req, int status) {
  free(req->data);
}

static void on_client_read(uvtls_t* tls, ssize_t nread, const uv_buf_t* buf) {
  if (nread < 0) {
    uvtls_close(tls, on_client_close);
    return;
  }

  {
    client_write_t* write = (client_write_t*) malloc(sizeof(client_write_t));
    uv_buf_t write_buf = uv_buf_init(write->buf, (unsigned int) nread);

    memcpy(write->buf, buf->base, (size_t) nread);
    write->req.data = write;
    uvtls_write(&write->req, tls, &write_buf, 1, on_client_write);
  }
}

static void on_client_alloc(uvtls_t* tls,
                            size_t suggested_size,
                            uv_buf_t* buf) {
  client_t* client = (client_t*) tls->data;
  buf->base = client->buf;
  buf->len = sizeof(client->buf);
}

static void on_accept(uvtls_t* client, int status) {
  uvtls_read_start(client, on_client_alloc, on_client_read);
}

void client_init(client_t* client, server_t* server) {
  int i;
  client->tls.data = client;
  client->server = server;

  FATAL(0 == uv_tcp_init(server->tcp.loop, &client->tcp));
  FATAL(0 == uvtls_init(&client->tls,
                        server->tls.context,
                        (uv_stream_t*) &client->tcp));

  for (i = 0; i < MAX_SERVER_CLIENTS; ++i) {
    if (!server->clients[i]) {
      break;
    }
  }

  if (i == MAX_SERVER_CLIENTS) abort();
  server->clients[i] = client;
}

static void on_close(uvtls_t* tls) {
  int i;
  server_t* server = (server_t*) tls->data;

  for (i = 0; i < MAX_SERVER_CLIENTS; ++i) {
    client_t* client = server->clients[i];
    if (client && !uvtls_is_closing(&client->tls)) {
      uvtls_close(&client->tls, on_client_close);
    }
  }
}

static void on_connection(uvtls_t* server, int status) {
  client_t* client = (client_t*) malloc(sizeof(client_t));

  client_init(client, (server_t*) server->data);
  uvtls_accept(server, &client->tls, on_accept);
}

static void on_async(uv_async_t* async) {
  server_t* server = (server_t*) async->data;
  uvtls_close(&server->tls, on_close);
  uv_close((uv_handle_t*) &server->async, NULL);
}

static void on_run(void* arg) {
  server_t* server = (server_t*) arg;
  FATAL(0 == uvtls_listen(&server->tls, 100, on_connection));
  uv_run(&server->loop, UV_RUN_DEFAULT);
}

void server_init(server_t* server) {
  struct sockaddr_in addr;
  uv_ip4_addr("0.0.0.0", SERVER_PORT, &addr);

  memset(server->clients, 0, sizeof(server->clients));
  server->tls.data = server;
  server->async.data = server;

  FATAL(0 == uv_loop_init(&server->loop));

  FATAL(0 == uv_tcp_init(&server->loop, &server->tcp));

  FATAL(0 == uv_async_init(&server->loop, &server->async, on_async));

  FATAL(0 == uv_tcp_bind(&server->tcp, (const struct sockaddr*) &addr, 0));

  FATAL(0 == uvtls_context_init(&server->tls_context, UVTLS_CONTEXT_LIB_INIT));

  FATAL(0 == uvtls_context_set_cert(
                 &server->tls_context, server_cert, strlen(server_cert)));

  FATAL(0 == uvtls_context_set_private_key(
                 &server->tls_context, server_key, strlen(server_key)));

  FATAL(0 == uvtls_init(&server->tls,
                        &server->tls_context,
                        (uv_stream_t*) &server->tcp));

  FATAL(0 == uv_thread_create(&server->thread, on_run, server));
}

void server_close(server_t* server) {
  uv_async_send(&server->async);
  uv_thread_join(&server->thread);
  uvtls_context_destroy(&server->tls_context);
}
