#include "test.h"

TEST_CASE_EXTERN(ring_buf);
TEST_CASE_EXTERN(client);

TEST_SUITE(uvtls)
  TEST_CASE_ENTRY(ring_buf)
  TEST_CASE_ENTRY(client)
  NULL
TEST_SUITE_END()

int main() {
  TEST_SUITE_RUN(uvtls);
}
