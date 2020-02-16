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

#ifndef TEST_UTILS_H
#define TEST_UTILS_H

#include <string.h>
#include <uv.h>

static void fill_pattern(char* buf, size_t size) {
  size_t i;
  const char* pattern = "012345678901234567890123456789012345678901";
  for (i = 0; i < size; ++i) {
    buf[i] = pattern[i % sizeof(pattern)];
  }
}

static void copy_bufs(uv_buf_t* bufs, int nbufs, char* out) {
  int i;
  char* data = out;
  for (i = 0; i < nbufs; ++i) {
    memcpy(data, bufs[i].base, bufs[i].len);
    data += bufs[i].len;
  }
}

#endif /* TEST_UTILS_H */
