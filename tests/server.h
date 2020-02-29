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

#ifndef TEST_SERVER_H
#define TEST_SERVER_H

#include "uvtls.h"

#define MAX_SERVER_CLIENTS 128
#define SERVER_PORT 65443

typedef struct server_s server_t;
typedef struct client_s client_t;
typedef struct client_write_s client_write_t;

struct client_s {
  uv_tcp_t tcp;
  uvtls_t tls;
  char buf[64 * 1024];
  server_t* server;
};

struct server_s {
  uv_tcp_t tcp;
  uvtls_t tls;
  uvtls_context_t tls_context;
  uv_thread_t thread;
  uv_loop_t loop;
  uv_async_t async;
  client_t* clients[MAX_SERVER_CLIENTS];
};

struct client_write_s {
  uvtls_write_t req;
  char buf[64 * 1024];
};


void server_init(server_t* server);
void server_close(server_t* server);

#endif /* TEST_SERVER_H */
