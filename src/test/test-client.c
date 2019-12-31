#include "test.h"

TEST(connect) {
}

TEST(verify) {
  /*ASSERT(0);*/
  ASSERT_INT8_EQ(1, 2);
  ASSERT_INT64_EQ(1, 2);
}

TEST_CASE_SETUP(client) {
}

TEST_CASE_TEARDOWN(client) {
}

TEST_CASE_EX(client)
  TEST_ENTRY(connect)
  TEST_ENTRY(verify)
  { NULL, NULL, OK }
TEST_CASE_END()
