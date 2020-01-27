find_package(PkgConfig)
if (PKG_CONFIG_FOUND)
  pkg_check_modules(PC_LIBUV QUIET libuv)
endif()

set(LIBUV_HINTS ${LIBUV_ROOT_DIR} ENV LIBUV_ROOT_DIR)

find_path(LIBUV_INCLUDE_DIR NAMES uv.h 
  HINTS ${LIBUV_HINTS}
  PATH_SUFFIXES include)

find_library(LIBUV_LIBRARY NAMES uv libuv
  HINTS ${LIBUV_HINTS}
  PATH_SUFFIXES lib)

mark_as_advanced(LIBUV_INCLUDE_DIR LIBUV_LIBRARY)

set(LIBUV_LIBRARIES ${LIBUV_LIBRARY})
set(LIBUV_INCLUDE_DIRS ${LIBUV_INCLUDE_DIR})

include(FindPackageHandleStandardArgs)

find_package_handle_standard_args(Libuv DEFAULT_MSG
                                  LIBUV_LIBRARY LIBUV_INCLUDE_DIR)

mark_as_advanced(LIBUV_INCLUDE_DIR LIBUV_LIBRARY)
