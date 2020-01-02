#include "uvtls.h"

#include <string.h>

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

#define UVTLS_ERR_NAME_GEN(name, _) \
  case UVTLS_##name:                \
    return #name;
const char* uvtls_err_name(int err) {
  switch (err) { UVTLS_ERRNO_MAP(UVTLS_ERR_NAME_GEN) }
  return uv_err_name(err);
}
#undef UVTLS_ERR_NAME_GEN

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

#define UVTLS_STRERROR_GEN(name, msg) \
  case UVTLS_##name:                  \
    return msg;
const char* uvtls_strerror(int err) {
  switch (err) { UVTLS_ERRNO_MAP(UVTLS_STRERROR_GEN) }
  return uv_strerror(err);
}
#undef UVTLS_STRERROR_GEN
