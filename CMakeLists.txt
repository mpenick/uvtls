cmake_minimum_required(VERSION 3.9)

project(uvtls VERSION 0.1 DESCRIPTION "TLS for libuv")

####

add_library(uvtls SHARED src/uvtls_openssl.c src/ring_buf.c)

set_target_properties(uvtls PROPERTIES VERSION ${PROJECT_VERSION})
set_target_properties(uvtls PROPERTIES SOVERSION 0)
set_target_properties(uvtls PROPERTIES PUBLIC_HEADER include/uvtls.h)

target_include_directories(uvtls PRIVATE include)
target_include_directories(uvtls PRIVATE src)

target_link_libraries(uvtls uv ssl crypto)

####

add_executable(test_client_server src/test_client_server.c)

target_include_directories(test_client_server PRIVATE include)
target_include_directories(test_client_server PRIVATE src)

target_link_libraries(test_client_server uvtls)

####

add_executable(test_ring_buf src/test_ring_buf.c src/ring_buf.c)

target_include_directories(test_ring_buf PRIVATE include)
target_include_directories(test_ring_buf PRIVATE src)
