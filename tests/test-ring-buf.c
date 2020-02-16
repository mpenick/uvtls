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

#include "test.h"

#include "ring-buf.h"
#include "utils.h"

#include <string.h>

TEST(one_block) {
  uvtls_ring_buf_t rb;
  char in[UVTLS_RING_BUF_BLOCK_SIZE];
  char out[UVTLS_RING_BUF_BLOCK_SIZE];

  fill_pattern(in, sizeof(in));

  ASSERT(0 == uvtls_ring_buf_init(&rb));
  ASSERT(0 == uvtls_ring_buf_size(&rb));
  ASSERT(0 == uvtls_ring_buf_read(&rb, out, sizeof(out)));

  uvtls_ring_buf_write(&rb, in, sizeof(in));
  ASSERT(sizeof(in) == uvtls_ring_buf_size(&rb));

  ASSERT(sizeof(out) == uvtls_ring_buf_read(&rb, out, sizeof(out)));
  ASSERT(0 == uvtls_ring_buf_size(&rb));
  ASSERT(0 == uvtls_ring_buf_read(&rb, out, sizeof(out)));

  ASSERT(memcmp(in, out, sizeof(in)) == 0);

  uvtls_ring_buf_destroy(&rb);
}

TEST(two_blocks) {
  uvtls_ring_buf_t rb;
  char in[UVTLS_RING_BUF_BLOCK_SIZE + 99];
  char out[UVTLS_RING_BUF_BLOCK_SIZE + 99];

  fill_pattern(in, sizeof(in));

  ASSERT(0 == uvtls_ring_buf_init(&rb));
  ASSERT(0 == uvtls_ring_buf_size(&rb));
  ASSERT(0 == uvtls_ring_buf_read(&rb, out, sizeof(out)));

  uvtls_ring_buf_write(&rb, in, sizeof(in));
  ASSERT(sizeof(in) == uvtls_ring_buf_size(&rb));

  ASSERT(sizeof(out) == uvtls_ring_buf_read(&rb, out, sizeof(out)));
  ASSERT(0 == uvtls_ring_buf_size(&rb));
  ASSERT(0 == uvtls_ring_buf_read(&rb, out, sizeof(out)));

  ASSERT(memcmp(in, out, sizeof(in)) == 0);

  uvtls_ring_buf_destroy(&rb);
}

TEST(tail_commit) {
  uvtls_ring_buf_t rb;
  char* data;
  char in[UVTLS_RING_BUF_BLOCK_SIZE + 99];
  char out[UVTLS_RING_BUF_BLOCK_SIZE + 99];

  fill_pattern(in, sizeof(in));

  ASSERT(0 == uvtls_ring_buf_init(&rb));

  ASSERT(UVTLS_RING_BUF_BLOCK_SIZE ==
         uvtls_ring_buf_tail_block(&rb, &data, UVTLS_RING_BUF_BLOCK_SIZE));

  memcpy(data, in, UVTLS_RING_BUF_BLOCK_SIZE);
  uvtls_ring_buf_tail_block_commit(&rb, UVTLS_RING_BUF_BLOCK_SIZE);
  ASSERT(UVTLS_RING_BUF_BLOCK_SIZE == uvtls_ring_buf_size(&rb));

  ASSERT(UVTLS_RING_BUF_BLOCK_SIZE ==
         uvtls_ring_buf_tail_block(&rb, &data, UVTLS_RING_BUF_BLOCK_SIZE));

  memcpy(data, in + UVTLS_RING_BUF_BLOCK_SIZE, 99);
  uvtls_ring_buf_tail_block_commit(&rb, 99);
  ASSERT(UVTLS_RING_BUF_BLOCK_SIZE + 99 == uvtls_ring_buf_size(&rb));

  ASSERT(sizeof(out) == uvtls_ring_buf_read(&rb, out, sizeof(out)));
  ASSERT(0 == uvtls_ring_buf_size(&rb));
  ASSERT(0 == uvtls_ring_buf_read(&rb, out, sizeof(out)));

  ASSERT(memcmp(in, out, sizeof(in)) == 0);

  uvtls_ring_buf_destroy(&rb);
}

TEST(head_commit_one_block) {
  uvtls_ring_buf_t rb;
  char in[UVTLS_RING_BUF_BLOCK_SIZE];
  char out[UVTLS_RING_BUF_BLOCK_SIZE];
  uvtls_ring_buf_pos_t to_commit;
  uv_buf_t bufs[2];
  int nbufs = 2;

  fill_pattern(in, sizeof(in));

  ASSERT(0 == uvtls_ring_buf_init(&rb));
  ASSERT(0 == uvtls_ring_buf_size(&rb));
  ASSERT(0 == uvtls_ring_buf_read(&rb, out, sizeof(out)));

  uvtls_ring_buf_write(&rb, in, sizeof(in));
  ASSERT(sizeof(in) == uvtls_ring_buf_size(&rb));

  to_commit = uvtls_ring_buf_head_blocks(&rb, rb.head, bufs, &nbufs);
  ASSERT(sizeof(in) == uvtls_ring_buf_size(&rb));

  ASSERT(rb.tail.block == to_commit.block);
  ASSERT(rb.tail.index == to_commit.index);

  ASSERT(1 == nbufs);
  ASSERT(UVTLS_RING_BUF_BLOCK_SIZE == (int) bufs[0].len);

  copy_bufs(bufs, nbufs, out);

  uvtls_ring_buf_head_blocks_commit(&rb, to_commit);
  ASSERT(0 == uvtls_ring_buf_size(&rb));

  ASSERT(memcmp(in, out, sizeof(in)) == 0);

  uvtls_ring_buf_destroy(&rb);
}

TEST(head_commit_one_block_partial_read) {
  uvtls_ring_buf_t rb;
  char in[UVTLS_RING_BUF_BLOCK_SIZE];
  char out[UVTLS_RING_BUF_BLOCK_SIZE];
  uvtls_ring_buf_pos_t to_commit;
  uv_buf_t bufs[2];
  int nbufs = 2;

  fill_pattern(in, sizeof(in));

  ASSERT(0 == uvtls_ring_buf_init(&rb));
  ASSERT(0 == uvtls_ring_buf_size(&rb));
  ASSERT(0 == uvtls_ring_buf_read(&rb, out, sizeof(out)));

  uvtls_ring_buf_write(&rb, in, sizeof(in));
  ASSERT(sizeof(in) == uvtls_ring_buf_size(&rb));

  ASSERT(99 == uvtls_ring_buf_read(&rb, out, 99));
  ASSERT(UVTLS_RING_BUF_BLOCK_SIZE - 99 == uvtls_ring_buf_size(&rb));

  to_commit = uvtls_ring_buf_head_blocks(&rb, rb.head, bufs, &nbufs);
  ASSERT(UVTLS_RING_BUF_BLOCK_SIZE - 99 == uvtls_ring_buf_size(&rb));

  ASSERT(rb.tail.block == to_commit.block);
  ASSERT(rb.tail.index == to_commit.index);

  ASSERT(1 == nbufs);
  ASSERT(UVTLS_RING_BUF_BLOCK_SIZE - 99 == (int) bufs[0].len);

  copy_bufs(bufs, nbufs, out + 99);

  uvtls_ring_buf_head_blocks_commit(&rb, to_commit);
  ASSERT(0 == uvtls_ring_buf_size(&rb));

  ASSERT(memcmp(in, out, sizeof(in)) == 0);

  uvtls_ring_buf_destroy(&rb);
}

TEST(head_commit_two_blocks) {
  uvtls_ring_buf_t rb;
  char in[UVTLS_RING_BUF_BLOCK_SIZE + 99];
  char out[UVTLS_RING_BUF_BLOCK_SIZE + 99];
  uvtls_ring_buf_pos_t to_commit;
  uv_buf_t bufs[2];
  int nbufs = 2;

  fill_pattern(in, sizeof(in));

  ASSERT(0 == uvtls_ring_buf_init(&rb));
  ASSERT(0 == uvtls_ring_buf_size(&rb));
  ASSERT(0 == uvtls_ring_buf_read(&rb, out, sizeof(out)));

  uvtls_ring_buf_write(&rb, in, sizeof(in));
  ASSERT(sizeof(in) == uvtls_ring_buf_size(&rb));

  to_commit = uvtls_ring_buf_head_blocks(&rb, rb.head, bufs, &nbufs);
  ASSERT(sizeof(in) == uvtls_ring_buf_size(&rb));

  ASSERT(rb.tail.block == to_commit.block);
  ASSERT(rb.tail.index == to_commit.index);

  ASSERT(2 == nbufs);
  ASSERT(UVTLS_RING_BUF_BLOCK_SIZE == (int) bufs[0].len);
  ASSERT(99 == (int) bufs[1].len);

  copy_bufs(bufs, nbufs, out);

  uvtls_ring_buf_head_blocks_commit(&rb, to_commit);
  ASSERT(0 == uvtls_ring_buf_size(&rb));

  ASSERT(memcmp(in, out, sizeof(in)) == 0);

  uvtls_ring_buf_destroy(&rb);
}

TEST(head_commit_two_blocks_read_to_next_block) {
  uvtls_ring_buf_t rb;
  char in[UVTLS_RING_BUF_BLOCK_SIZE + 99];
  char out[UVTLS_RING_BUF_BLOCK_SIZE + 99];
  uvtls_ring_buf_pos_t to_commit;
  uv_buf_t bufs[2];
  int nbufs = 2;

  fill_pattern(in, sizeof(in));

  ASSERT(0 == uvtls_ring_buf_init(&rb));
  ASSERT(0 == uvtls_ring_buf_size(&rb));
  ASSERT(0 == uvtls_ring_buf_read(&rb, out, sizeof(out)));

  uvtls_ring_buf_write(&rb, in, sizeof(in));
  ASSERT(sizeof(in) == uvtls_ring_buf_size(&rb));

  ASSERT(UVTLS_RING_BUF_BLOCK_SIZE ==
         uvtls_ring_buf_read(&rb, out, UVTLS_RING_BUF_BLOCK_SIZE));
  ASSERT(99 == uvtls_ring_buf_size(&rb));

  to_commit = uvtls_ring_buf_head_blocks(&rb, rb.head, bufs, &nbufs);
  ASSERT(rb.tail.block == to_commit.block);
  ASSERT(rb.tail.index == to_commit.index);

  ASSERT(1 == nbufs);
  ASSERT(99 == (int) bufs[0].len);

  copy_bufs(bufs, nbufs, out + UVTLS_RING_BUF_BLOCK_SIZE);

  uvtls_ring_buf_head_blocks_commit(&rb, to_commit);
  ASSERT(0 == uvtls_ring_buf_size(&rb));

  ASSERT(memcmp(in, out, sizeof(in)) == 0);

  uvtls_ring_buf_destroy(&rb);
}

TEST(head_commit_two_blocks_partial_read) {
  uvtls_ring_buf_t rb;
  char in[UVTLS_RING_BUF_BLOCK_SIZE + 99];
  char out[UVTLS_RING_BUF_BLOCK_SIZE + 99];
  uvtls_ring_buf_pos_t to_commit;
  uv_buf_t bufs[2];
  int nbufs = 2;

  fill_pattern(in, sizeof(in));

  ASSERT(0 == uvtls_ring_buf_init(&rb));
  ASSERT(0 == uvtls_ring_buf_size(&rb));
  ASSERT(0 == uvtls_ring_buf_read(&rb, out, sizeof(out)));

  uvtls_ring_buf_write(&rb, in, sizeof(in));
  ASSERT(sizeof(in) == uvtls_ring_buf_size(&rb));

  ASSERT(99 == uvtls_ring_buf_read(&rb, out, 99));
  ASSERT(UVTLS_RING_BUF_BLOCK_SIZE == uvtls_ring_buf_size(&rb));

  to_commit = uvtls_ring_buf_head_blocks(&rb, rb.head, bufs, &nbufs);
  ASSERT(rb.tail.block == to_commit.block);
  ASSERT(rb.tail.index == to_commit.index);

  ASSERT(2 == nbufs);
  ASSERT(UVTLS_RING_BUF_BLOCK_SIZE - 99 == (int) bufs[0].len);
  ASSERT(99 == (int) bufs[1].len);

  copy_bufs(bufs, nbufs, out + 99);

  uvtls_ring_buf_head_blocks_commit(&rb, to_commit);
  ASSERT(0 == uvtls_ring_buf_size(&rb));

  ASSERT(memcmp(in, out, sizeof(in)) == 0);

  uvtls_ring_buf_destroy(&rb);
}

TEST(reset) {
  uvtls_ring_buf_t rb;
  char in[UVTLS_RING_BUF_BLOCK_SIZE + 99];
  char out[UVTLS_RING_BUF_BLOCK_SIZE + 99];

  fill_pattern(in, sizeof(in));

  ASSERT(0 == uvtls_ring_buf_init(&rb));
  ASSERT(0 == uvtls_ring_buf_size(&rb));
  ASSERT(0 == uvtls_ring_buf_read(&rb, out, sizeof(out)));

  uvtls_ring_buf_write(&rb, in, sizeof(in));
  ASSERT(sizeof(in) == uvtls_ring_buf_size(&rb));

  uvtls_ring_buf_reset(&rb);
  ASSERT(0 == uvtls_ring_buf_size(&rb));

  uvtls_ring_buf_write(&rb, in, sizeof(in));
  ASSERT(sizeof(in) == uvtls_ring_buf_size(&rb));

  ASSERT(sizeof(out) == uvtls_ring_buf_read(&rb, out, sizeof(out)));
  ASSERT(0 == uvtls_ring_buf_size(&rb));

  ASSERT(memcmp(in, out, sizeof(in)) == 0);

  uvtls_ring_buf_destroy(&rb);
}

TEST_CASE_BEGIN(ring_buf)
  TEST_ENTRY(one_block)
  TEST_ENTRY(two_blocks)
  TEST_ENTRY(tail_commit)
  TEST_ENTRY(head_commit_one_block)
  TEST_ENTRY(head_commit_one_block_partial_read)
  TEST_ENTRY(head_commit_two_blocks)
  TEST_ENTRY(head_commit_two_blocks_read_to_next_block)
  TEST_ENTRY(head_commit_two_blocks_partial_read)
  TEST_ENTRY_LAST()
TEST_CASE_END()
