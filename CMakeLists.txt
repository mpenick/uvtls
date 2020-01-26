cmake_minimum_required(VERSION 3.9)

project(uvtls VERSION 0.1 DESCRIPTION "TLS for libuv")

####

add_library(uvtls SHARED src/uvtls-openssl.c src/uvtls-common.c src/ring-buf.c src/curl-hostcheck.c)

set_target_properties(uvtls PROPERTIES VERSION ${PROJECT_VERSION})
set_target_properties(uvtls PROPERTIES SOVERSION 0)
set_target_properties(uvtls PROPERTIES PUBLIC_HEADER include/uvtls.h)

target_include_directories(uvtls PRIVATE include)
target_include_directories(uvtls PRIVATE src)

target_link_libraries(uvtls uv ssl crypto)

####

add_executable(test-uvtls src/test/main.c src/test/test.c src/test/server.c src/test/test-ring-buf.c src/test/test-client.c)

target_include_directories(test-uvtls PRIVATE include)
target_include_directories(test-uvtls PRIVATE src)

target_link_libraries(test-uvtls uvtls uv)
