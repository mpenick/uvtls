#include "test.h"

#include "ring-buf.h"

#include <string.h>

TEST(simple) {
  char in[UVTLS_RING_BUF_BLOCK_SIZE];
  char out[UVTLS_RING_BUF_BLOCK_SIZE];
  uvtls_ring_buf_t rb;

  memset(in, 0x61626364, UVTLS_RING_BUF_BLOCK_SIZE);

  ASSERT_INT_EQ(0, uvtls_ring_buf_init(&rb));
  EXPECT_INT_EQ(0, uvtls_ring_buf_size(&rb));
  EXPECT_INT_EQ(0, uvtls_ring_buf_read(&rb, out, sizeof(out)));

  uvtls_ring_buf_write(&rb, in, sizeof(in));
  EXPECT_INT_EQ(UVTLS_RING_BUF_BLOCK_SIZE, uvtls_ring_buf_size(&rb));

  EXPECT_INT_EQ(UVTLS_RING_BUF_BLOCK_SIZE,
                uvtls_ring_buf_read(&rb, out, sizeof(out)));
  EXPECT_INT_EQ(0, uvtls_ring_buf_size(&rb));

  EXPECT_MEMCMP_EQ(in, out, UVTLS_RING_BUF_BLOCK_SIZE);

  EXPECT_MEMCMP_EQ("abc", out, UVTLS_RING_BUF_BLOCK_SIZE);

  uvtls_ring_buf_destroy(&rb);
}

TEST(reset) {
}

TEST_CASE_BEGIN(ring_buf)
  TEST_ENTRY(simple)
  TEST_ENTRY(reset)
  TEST_ENTRY_LAST()
TEST_CASE_END()
