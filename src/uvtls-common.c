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

#include "uvtls.h"

#include <string.h>

#define UVTLS_ERR_NAME_GEN(name, _) \
  case UVTLS_##name:                \
    return #name;
const char* uvtls_err_name(int err) {
  switch (err) { UVTLS_ERRNO_MAP(UVTLS_ERR_NAME_GEN) }
  return uv_err_name(err);
}
#undef UVTLS_ERR_NAME_GEN

#if UV_VERSION_HEX >= 012200
#define UVTLS_ERR_NAME_GEN_R(name, _) \
  case UVTLS_##name:                  \
    strncpy(buf, #name, buflen);      \
    break;
char* uvtls_err_name_r(int err, char* buf, size_t buflen) {
  switch (err) {
    UVTLS_ERRNO_MAP(UVTLS_ERR_NAME_GEN_R)
    default:
      uv_err_name_r(err, buf, buflen);
  }
  return buf;
}
#undef UVTLS_ERR_NAME_GEN_R
#endif

#define UVTLS_STRERROR_GEN(name, msg) \
  case UVTLS_##name:                  \
    return msg;
const char* uvtls_strerror(int err) {
  switch (err) { UVTLS_ERRNO_MAP(UVTLS_STRERROR_GEN) }
  return uv_strerror(err);
}
#undef UVTLS_STRERROR_GEN

#if UV_VERSION_HEX >= 012200
#define UVTLS_STRERROR_GEN_R(name, msg) \
  case UVTLS_##name:                    \
    snprintf(buf, buflen, "%s", msg);   \
    break;
char* uvtls_strerror_r(int err, char* buf, size_t buflen) {
  switch (err) {
    UVTLS_ERRNO_MAP(UVTLS_STRERROR_GEN_R)
    default:
      uv_strerror_r(err, buf, buflen);
  }
  return buf;
}
#undef UVTLS_STRERROR_GEN_R
#endif
