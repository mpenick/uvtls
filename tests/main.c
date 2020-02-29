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
#include "uvtls.h"

#if defined(_MSC_VER) && defined(_DEBUG)
#include <crtdbg.h>
void redirect_error_to_console() {
  // disable the "application crashed" popup
  SetErrorMode(SEM_FAILCRITICALERRORS |
               SEM_NOGPFAULTERRORBOX |
               SEM_NOOPENFILEERRORBOX);

  // redirect assert, error and warning messages to console
  _CrtSetReportMode(_CRT_ASSERT, _CRTDBG_MODE_FILE);
  _CrtSetReportFile(_CRT_ASSERT, _CRTDBG_FILE_STDERR);
  _CrtSetReportMode(_CRT_ERROR, _CRTDBG_MODE_FILE);
  _CrtSetReportFile(_CRT_ERROR, _CRTDBG_FILE_STDERR);
  _CrtSetReportMode(_CRT_WARN, _CRTDBG_MODE_FILE);
  _CrtSetReportFile(_CRT_WARN, _CRTDBG_FILE_STDERR);

  // disable stdio & stderr output buffering
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);
}
#endif

TEST_CASE_EXTERN(ring_buf);
TEST_CASE_EXTERN(client);

TEST_SUITE_BEGIN(uvtls)
  TEST_CASE_ENTRY(ring_buf)
  TEST_CASE_ENTRY(client)
  TEST_CASE_ENTRY_LAST()
TEST_SUITE_END()

int main(int argc, char** argv) {
  #if defined(_MSC_VER) && defined(_DEBUG)
    redirect_error_to_console();
  #endif
  return TEST_RUN_SUITE(uvtls, argc, argv);
}
