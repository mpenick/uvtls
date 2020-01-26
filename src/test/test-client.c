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

#include <assert.h>
#include <stdlib.h>

#include "certs.h"
#include "server.h"
#include "test.h"
#include "utils.h"

typedef struct client_test_s client_test_t;

static server_t server;


struct client_test_s {
  uv_tcp_t tcp;
  uvtls_t tls;
  uvtls_connect_t connect_req;
  uvtls_write_t write_req;
  char read_buf[64 * 1024];
  char in[UVTLS_RING_BUF_BLOCK_SIZE + 1];
  char out[UVTLS_RING_BUF_BLOCK_SIZE + 1];
  size_t nbytes;
  int was_close_cb_called;
  int was_connect_cb_called;
};

static void on_close(uvtls_t* tls) {
  client_test_t* client = (client_test_t*) tls->data;
  client->was_close_cb_called = 1;
}

static void on_alloc(uvtls_t* tls, size_t suggested_size, uv_buf_t* buf) {
  client_test_t* client = (client_test_t*) tls->data;
  buf->base = client->read_buf;
  buf->len = sizeof(client->read_buf);
}

static void on_read(uvtls_t* tls, ssize_t nread, const uv_buf_t* buf) {
  size_t i;
  client_test_t* client = (client_test_t*) tls->data;

  FATAL(0 < nread);

  size_t to_copy = (size_t) nread;
  ptrdiff_t remaining = sizeof(client->out) - client->nbytes;
  if (to_copy > (size_t) remaining) {
    to_copy = (size_t) remaining;
  }

  memcpy(client->out + client->nbytes, buf->base, to_copy);
  client->nbytes += to_copy;

  for (i = 0; i < (size_t) nread; ++i) {
    if (buf->base[i] == '\0') {
      uvtls_close(tls, on_close);
      return;
    }
  }
}

static void on_write(uvtls_write_t* req, int status) {
  uvtls_read_start(req->tls, on_alloc, on_read);
}


static void on_connect(uvtls_connect_t* req, int status) {
  client_test_t* client = (client_test_t*) req->tls->data;

  uv_buf_t buf;

  FATAL(0 == status);

  buf.base = client->in;
  buf.len = sizeof(client->in);
  uvtls_write(&client->write_req, req->tls, &buf, 1, on_write);
}

static void on_tcp_connect(uv_connect_t* req, int status) {
  client_test_t* client = (client_test_t*) req->data;
  uvtls_connect(&client->connect_req, &client->tls, on_connect);
}

TEST(connect) {
  uv_loop_t loop;
  client_test_t client;

  uvtls_context_t tls_context;
  uv_connect_t connect_req;

  fill_pattern(client.in, sizeof(client.in));
  client.in[UVTLS_RING_BUF_BLOCK_SIZE] = '\0';

  memset(client.out, 0, sizeof(client.out));

  struct sockaddr_in addr;
  uv_ip4_addr("127.0.0.1", SERVER_PORT, &addr);

  ASSERT(0 == uv_loop_init(&loop));
  ASSERT(0 == uv_tcp_init(&loop, &client.tcp));

  ASSERT(0 == uvtls_context_init(&tls_context, UVTLS_CONTEXT_LIB_INIT));

  uvtls_context_set_verify_flags(&tls_context, UVTLS_VERIFY_NONE);

  client.tls.data = &client;
  client.nbytes = 0;
  client.was_close_cb_called = 0;
  ASSERT(0 ==
         uvtls_init(&client.tls, &tls_context, (uv_stream_t*) &client.tcp));

  connect_req.data = &client;
  ASSERT(0 == uv_tcp_connect(&connect_req,
                             &client.tcp,
                             (const struct sockaddr*) &addr,
                             on_tcp_connect));

  uv_run(&loop, UV_RUN_DEFAULT);

  ASSERT(sizeof(client.in) == client.nbytes);
  ASSERT(memcmp(client.in, client.out, sizeof(client.in)) == 0);
  ASSERT(client.was_close_cb_called);

  uvtls_context_destroy(&tls_context);
  uv_loop_close(&loop);
}

static void on_connect_verify_cert(uvtls_connect_t* req, int status) {
  client_test_t* client = (client_test_t*) req->tls->data;
  client->was_connect_cb_called = 1;
  ASSERT(0 == status);
  uvtls_close(req->tls, on_close);
}

static void on_tcp_connect_verify_cert(uv_connect_t* req, int status) {
  client_test_t* client = (client_test_t*) req->data;
  uvtls_connect(&client->connect_req, &client->tls, on_connect_verify_cert);
}

TEST(verify_peer_cert) {
  uv_loop_t loop;
  client_test_t client;

  uvtls_context_t tls_context;
  uv_connect_t connect_req;

  struct sockaddr_in addr;
  uv_ip4_addr("127.0.0.1", SERVER_PORT, &addr);

  ASSERT(0 == uv_loop_init(&loop));
  ASSERT(0 == uv_tcp_init(&loop, &client.tcp));

  ASSERT(0 == uvtls_context_init(&tls_context, UVTLS_CONTEXT_LIB_INIT));

  ASSERT(0 == uvtls_context_add_trusted_certs(
                  &tls_context, server_cert, strlen(server_cert)));

  uvtls_context_set_verify_flags(&tls_context, UVTLS_VERIFY_PEER_CERT);

  client.tls.data = &client;
  client.was_connect_cb_called = 0;
  client.was_close_cb_called = 0;
  ASSERT(0 ==
         uvtls_init(&client.tls, &tls_context, (uv_stream_t*) &client.tcp));

  connect_req.data = &client;
  ASSERT(0 == uv_tcp_connect(&connect_req,
                             &client.tcp,
                             (const struct sockaddr*) &addr,
                             on_tcp_connect_verify_cert));

  uv_run(&loop, UV_RUN_DEFAULT);
  ASSERT(client.was_connect_cb_called);
  ASSERT(client.was_close_cb_called);

  uvtls_context_destroy(&tls_context);
  uv_loop_close(&loop);
}

static void on_connect_bad_cert(uvtls_connect_t* req, int status) {
  client_test_t* client = (client_test_t*) req->tls->data;
  client->was_connect_cb_called = 1;
  ASSERT(UVTLS_EBADPEERCERT == status);
  uvtls_close(req->tls, on_close);
}

static void on_tcp_connect_bad_cert(uv_connect_t* req, int status) {
  client_test_t* client = (client_test_t*) req->data;
  uvtls_connect(&client->connect_req, &client->tls, on_connect_bad_cert);
}

TEST(verify_bad_peer_cert) {
  uv_loop_t loop;
  client_test_t client;

  uvtls_context_t tls_context;
  uv_connect_t connect_req;

  struct sockaddr_in addr;
  uv_ip4_addr("127.0.0.1", SERVER_PORT, &addr);

  ASSERT(0 == uv_loop_init(&loop));
  ASSERT(0 == uv_tcp_init(&loop, &client.tcp));

  ASSERT(0 == uvtls_context_init(&tls_context, UVTLS_CONTEXT_LIB_INIT));

  uvtls_context_set_verify_flags(&tls_context, UVTLS_VERIFY_PEER_CERT);

  client.tls.data = &client;
  client.was_connect_cb_called = 0;
  client.was_close_cb_called = 0;
  ASSERT(0 ==
         uvtls_init(&client.tls, &tls_context, (uv_stream_t*) &client.tcp));

  connect_req.data = &client;
  ASSERT(0 == uv_tcp_connect(&connect_req,
                             &client.tcp,
                             (const struct sockaddr*) &addr,
                             on_tcp_connect_bad_cert));

  uv_run(&loop, UV_RUN_DEFAULT);
  ASSERT(client.was_connect_cb_called);
  ASSERT(client.was_close_cb_called);

  uvtls_context_destroy(&tls_context);
  uv_loop_close(&loop);
}

static void on_connect_bad_ident(uvtls_connect_t* req, int status) {
  client_test_t* client = (client_test_t*) req->tls->data;
  client->was_connect_cb_called = 1;
  ASSERT(UVTLS_EBADPEERIDENT == status);
  uvtls_close(req->tls, on_close);
}

static void on_tcp_connect_bad_ident(uv_connect_t* req, int status) {
  client_test_t* client = (client_test_t*) req->data;
  uvtls_connect(&client->connect_req, &client->tls, on_connect_bad_ident);
}

TEST(verify_bad_peer_ident) {
  uv_loop_t loop;
  client_test_t client;

  uvtls_context_t tls_context;
  uv_connect_t connect_req;

  struct sockaddr_in addr;
  uv_ip4_addr("127.0.0.1", SERVER_PORT, &addr);

  ASSERT(0 == uv_loop_init(&loop));
  ASSERT(0 == uv_tcp_init(&loop, &client.tcp));

  ASSERT(0 == uvtls_context_init(&tls_context, UVTLS_CONTEXT_LIB_INIT));

  uvtls_context_set_verify_flags(&tls_context, UVTLS_VERIFY_PEER_IDENT);

  client.tls.data = &client;
  client.was_connect_cb_called = 0;
  client.was_close_cb_called = 0;
  ASSERT(0 ==
         uvtls_init(&client.tls, &tls_context, (uv_stream_t*) &client.tcp));

  ASSERT(0 == uvtls_set_hostname(&client.tls, "invalid", strlen("invalid")));

  connect_req.data = &client;
  ASSERT(0 == uv_tcp_connect(&connect_req,
                             &client.tcp,
                             (const struct sockaddr*) &addr,
                             on_tcp_connect_bad_ident));

  uv_run(&loop, UV_RUN_DEFAULT);
  ASSERT(client.was_connect_cb_called);
  ASSERT(client.was_close_cb_called);

  uvtls_context_destroy(&tls_context);
  uv_loop_close(&loop);
}

static void on_connect_verify_ident(uvtls_connect_t* req, int status) {
  client_test_t* client = (client_test_t*) req->tls->data;
  client->was_connect_cb_called = 1;
  ASSERT(0 == status);
  uvtls_close(req->tls, on_close);
}

static void on_tcp_connect_verify_ident(uv_connect_t* req, int status) {
  client_test_t* client = (client_test_t*) req->data;
  uvtls_connect(&client->connect_req, &client->tls, on_connect_verify_ident);
}

TEST(verify_peer_ident) {
  uv_loop_t loop;
  client_test_t client;

  uvtls_context_t tls_context;
  uv_connect_t connect_req;

  struct sockaddr_in addr;
  uv_ip4_addr("127.0.0.1", SERVER_PORT, &addr);

  ASSERT(0 == uv_loop_init(&loop));
  ASSERT(0 == uv_tcp_init(&loop, &client.tcp));

  ASSERT(0 == uvtls_context_init(&tls_context, UVTLS_CONTEXT_LIB_INIT));

  uvtls_context_set_verify_flags(&tls_context, UVTLS_VERIFY_PEER_IDENT);

  client.tls.data = &client;
  client.was_connect_cb_called = 0;
  client.was_close_cb_called = 0;
  ASSERT(0 ==
         uvtls_init(&client.tls, &tls_context, (uv_stream_t*) &client.tcp));

  ASSERT(0 == uvtls_set_hostname(&client.tls, "uvtls", strlen("uvtls")));

  connect_req.data = &client;
  ASSERT(0 == uv_tcp_connect(&connect_req,
                             &client.tcp,
                             (const struct sockaddr*) &addr,
                             on_tcp_connect_verify_ident));

  uv_run(&loop, UV_RUN_DEFAULT);
  ASSERT(client.was_connect_cb_called);
  ASSERT(client.was_close_cb_called);

  uvtls_context_destroy(&tls_context);
  uv_loop_close(&loop);
}

TEST_CASE_SETUP(client) {
  server_init(&server);
}

TEST_CASE_TEARDOWN(client) {
  server_close(&server);
}

TEST_CASE_BEGIN_EX(client)
  TEST_ENTRY(connect)
  TEST_ENTRY(verify_peer_cert)
  TEST_ENTRY(verify_bad_peer_cert)
  TEST_ENTRY(verify_peer_ident)
  TEST_ENTRY(verify_bad_peer_ident)
  TEST_ENTRY_LAST()
TEST_CASE_END()
