cmake_minimum_required(VERSION 3.9)

project(uvtls VERSION 0.1 DESCRIPTION "TLS for libuv")

####

add_library(uvtls SHARED src/uvtls_openssl.c)

set_target_properties(uvtls PROPERTIES VERSION ${PROJECT_VERSION})
set_target_properties(uvtls PROPERTIES SOVERSION 0)
set_target_properties(uvtls PROPERTIES PUBLIC_HEADER include/uvtls.h)

target_include_directories(uvtls PRIVATE include)
target_include_directories(uvtls PRIVATE src)

target_link_libraries(uvtls uv)

####

add_executable(uvtls_test src/ringbuffer.c src/test.c src/uvtls_openssl.c)

target_include_directories(uvtls_test PRIVATE include)
target_include_directories(uvtls_test PRIVATE src)

target_link_libraries(uvtls_test uv ssl crypto)
