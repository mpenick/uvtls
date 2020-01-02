#include "test.h"

TEST_CASE_EXTERN(ring_buf);
TEST_CASE_EXTERN(client);

TEST_SUITE_BEGIN(uvtls)
  TEST_CASE_ENTRY(ring_buf)
  TEST_CASE_ENTRY(client)
  TEST_CASE_ENTRY_LAST()
TEST_SUITE_END()

int main(int argc, char** argv) {
  TEST_SUITE_RUN(uvtls, argc, argv);
}
