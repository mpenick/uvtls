#include "test.h"

TEST(connect) {
}

TEST(verify) {
}

TEST_CASE_SETUP(client) {
}

TEST_CASE_TEARDOWN(client) {
}

TEST_CASE_BEGIN_EX(client)
  TEST_ENTRY(connect)
  TEST_ENTRY(verify)
  TEST_ENTRY_LAST()
TEST_CASE_END()
