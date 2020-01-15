/* Copyright Michael A. Penick
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is furnished to do
 * so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "test.h"

#include "ring-buf.h"

#include <string.h>

void fill_pattern(char* buf, size_t size) {
  size_t i;
  const char* pattern = "012345678901234567890123456789012345678901";
  for (i = 0; i < size; ++i) {
    buf[i] = pattern[i % sizeof(pattern)];
  }
}

TEST(single) {
  uvtls_ring_buf_t rb;
  char in[UVTLS_RING_BUF_BLOCK_SIZE];
  char out[UVTLS_RING_BUF_BLOCK_SIZE];

  fill_pattern(in, sizeof(in));

  ASSERT_INT_EQ(0, uvtls_ring_buf_init(&rb));
  EXPECT_INT_EQ(0, uvtls_ring_buf_size(&rb));
  EXPECT_INT_EQ(0, uvtls_ring_buf_read(&rb, out, sizeof(out)));

  uvtls_ring_buf_write(&rb, in, sizeof(in));
  EXPECT_INT_EQ(sizeof(in), uvtls_ring_buf_size(&rb));

  EXPECT_INT_EQ(sizeof(out), uvtls_ring_buf_read(&rb, out, sizeof(out)));
  EXPECT_INT_EQ(0, uvtls_ring_buf_size(&rb));
  EXPECT_INT_EQ(0, uvtls_ring_buf_read(&rb, out, sizeof(out)));

  EXPECT_MEMCMP_EQ(in, out, sizeof(in));

  uvtls_ring_buf_destroy(&rb);
}

TEST(overlap) {
  uvtls_ring_buf_t rb;
  char in[UVTLS_RING_BUF_BLOCK_SIZE + 1];
  char out[UVTLS_RING_BUF_BLOCK_SIZE + 1];

  fill_pattern(in, sizeof(in));

  ASSERT_INT_EQ(0, uvtls_ring_buf_init(&rb));
  EXPECT_INT_EQ(0, uvtls_ring_buf_size(&rb));
  EXPECT_INT_EQ(0, uvtls_ring_buf_read(&rb, out, sizeof(out)));

  uvtls_ring_buf_write(&rb, in, sizeof(in));
  EXPECT_INT_EQ(sizeof(in), uvtls_ring_buf_size(&rb));

  EXPECT_INT_EQ(sizeof(out), uvtls_ring_buf_read(&rb, out, sizeof(out)));
  EXPECT_INT_EQ(0, uvtls_ring_buf_size(&rb));
  EXPECT_INT_EQ(0, uvtls_ring_buf_read(&rb, out, sizeof(out)));

  EXPECT_MEMCMP_EQ(in, out, sizeof(in));

  uvtls_ring_buf_destroy(&rb);
}

TEST(tail_commit) {
  uvtls_ring_buf_t rb;
  char* data;
  char in[UVTLS_RING_BUF_BLOCK_SIZE + 1];
  char out[UVTLS_RING_BUF_BLOCK_SIZE + 1];

  fill_pattern(in, sizeof(in));

  ASSERT_INT_EQ(0, uvtls_ring_buf_init(&rb));

  EXPECT_INT_EQ(
      UVTLS_RING_BUF_BLOCK_SIZE,
      uvtls_ring_buf_tail_block(&rb, &data, UVTLS_RING_BUF_BLOCK_SIZE));

  memcpy(data, in, UVTLS_RING_BUF_BLOCK_SIZE);
  uvtls_ring_buf_tail_block_commit(&rb, UVTLS_RING_BUF_BLOCK_SIZE);
  EXPECT_INT_EQ(UVTLS_RING_BUF_BLOCK_SIZE, uvtls_ring_buf_size(&rb));

  EXPECT_INT_EQ(
      UVTLS_RING_BUF_BLOCK_SIZE,
      uvtls_ring_buf_tail_block(&rb, &data, UVTLS_RING_BUF_BLOCK_SIZE));

  memcpy(data, in + UVTLS_RING_BUF_BLOCK_SIZE, 1);
  uvtls_ring_buf_tail_block_commit(&rb, 1);
  EXPECT_INT_EQ(UVTLS_RING_BUF_BLOCK_SIZE + 1, uvtls_ring_buf_size(&rb));

  EXPECT_INT_EQ(sizeof(out), uvtls_ring_buf_read(&rb, out, sizeof(out)));
  EXPECT_INT_EQ(0, uvtls_ring_buf_size(&rb));
  EXPECT_INT_EQ(0, uvtls_ring_buf_read(&rb, out, sizeof(out)));

  EXPECT_MEMCMP_EQ(in, out, sizeof(in));

  uvtls_ring_buf_destroy(&rb);
}

TEST(head_commit) {
  uvtls_ring_buf_t rb;
  char in[UVTLS_RING_BUF_BLOCK_SIZE + 1];
  char out[UVTLS_RING_BUF_BLOCK_SIZE + 1];
  uvtls_ring_buf_pos_t to_commit;
  uv_buf_t bufs[2];
  int nbufs = 2;

  fill_pattern(in, sizeof(in));

  ASSERT_INT_EQ(0, uvtls_ring_buf_init(&rb));
  EXPECT_INT_EQ(0, uvtls_ring_buf_size(&rb));
  EXPECT_INT_EQ(0, uvtls_ring_buf_read(&rb, out, sizeof(out)));

  uvtls_ring_buf_write(&rb, in, sizeof(in));
  EXPECT_INT_EQ(sizeof(in), uvtls_ring_buf_size(&rb));

  to_commit = uvtls_ring_buf_head_blocks(&rb, rb.head, bufs, &nbufs);
  EXPECT_INT_EQ(sizeof(in), uvtls_ring_buf_size(&rb));

  ASSERT_PTR_EQ(rb.tail.block, to_commit.block);
  ASSERT_INT_EQ(rb.tail.index, to_commit.index);

  ASSERT_INT_EQ(2, nbufs);
  ASSERT_INT_EQ(UVTLS_RING_BUF_BLOCK_SIZE, (int) bufs[0].len);
  ASSERT_INT_EQ(1, (int) bufs[1].len);

  { /* Copy bufs into out block */
    int i;
    char* data = out;
    for (i = 0; i < nbufs; ++i) {
      memcpy(data, bufs[i].base, bufs[i].len);
      data += bufs[i].len;
    }
  }

  uvtls_ring_buf_head_blocks_commit(&rb, to_commit);
  EXPECT_INT_EQ(0, uvtls_ring_buf_size(&rb));

  EXPECT_MEMCMP_EQ(in, out, sizeof(in));

  uvtls_ring_buf_destroy(&rb);
}

TEST(reset) {
}

TEST_CASE_BEGIN(ring_buf)
  TEST_ENTRY(single)
  TEST_ENTRY(overlap)
  TEST_ENTRY(tail_commit)
  TEST_ENTRY(head_commit)
  TEST_ENTRY_LAST()
TEST_CASE_END()
