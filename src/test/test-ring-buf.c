#include "test.h"

#include "ring-buf.h"

#include <string.h>

TEST(single) {
  uvtls_ring_buf_t rb;
  char in[UVTLS_RING_BUF_BLOCK_SIZE];
  char out[UVTLS_RING_BUF_BLOCK_SIZE];

  memset(in, 0x61626364, sizeof(in));

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

  memset(in, 0x61626364, sizeof(in));

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

TEST(reset) {
}

TEST_CASE_BEGIN(ring_buf)
  TEST_ENTRY(single)
  TEST_ENTRY(overlap)
  TEST_ENTRY(reset)
  TEST_ENTRY_LAST()
TEST_CASE_END()
