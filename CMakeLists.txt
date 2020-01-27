cmake_minimum_required(VERSION 3.9)
project(uvtls VERSION 0.1 DESCRIPTION "TLS for libuv")

list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")

include(FindLibuv)

list(APPEND LIBRARIES ${LIBUV_LIBRARIES})
list(APPEND INCLUDE_DIRS ${LIBUV_INCLUDE_DIRS})

####

option(BUILD_SHARED_LIBS "Build shared library" OFF)
option(TLS_BACKEND "TLS/SSL library to use for the backend")


if(${TLS_BACKEND} STREQUAL "OpenSSL" OR NOT TLS_BACKEND)
  find_package(OpenSSL)

  if (OPENSSL_FOUND)
    set(TLS_BACKEND "OpenSSL")
  endif()

  list(APPEND LIBRARIES ${OPENSSL_LIBRARIES})
  list(APPEND INCLUDE_DIRS ${OPENSSL_INCLUDE_DIR})
endif()

####

add_library(uvtls src/uvtls-openssl.c src/uvtls-common.c src/ring-buf.c src/curl-hostcheck.c)

set_target_properties(uvtls PROPERTIES VERSION ${PROJECT_VERSION})
set_target_properties(uvtls PROPERTIES SOVERSION 0)
set_target_properties(uvtls PROPERTIES PUBLIC_HEADER include/uvtls.h)

target_include_directories(uvtls PRIVATE include)
target_include_directories(uvtls PRIVATE src)
target_include_directories(uvtls PRIVATE ${INCLUDE_DIRS})

target_link_libraries(uvtls ${LIBRARIES})

####

include(GNUInstallDirs)

install(FILES
  ${PROJECT_SOURCE_DIR}/include/uvtls/internal.h
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/uvtls)

install(TARGETS uvtls
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

configure_file(uvtls.pc.in uvtls.pc @ONLY)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/uvtls.pc
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)

####

add_executable(test-uvtls src/test/main.c src/test/test.c src/test/server.c src/test/test-ring-buf.c src/test/test-client.c)

target_include_directories(test-uvtls PRIVATE include)
target_include_directories(test-uvtls PRIVATE src)
target_include_directories(uvtls PRIVATE ${INCLUDE_DIRS})

target_link_libraries(test-uvtls uvtls ${LIBRARIES})
