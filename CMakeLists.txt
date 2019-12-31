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

add_executable(test-uvtls src/test/main.c src/test/test-ring-buf.c src/test/test-client.c)

target_link_libraries(test-uvtls uvtls uv)

####

add_executable(test-client-server src/test-client-server.c)

target_include_directories(test-client-server PRIVATE include)
target_include_directories(test-client-server PRIVATE src)

target_link_libraries(test-client-server uvtls)

####

add_executable(test-bh-client src/test-bh-client.c)

target_include_directories(test-bh-client PRIVATE include)
target_include_directories(test-bh-client PRIVATE src)

target_link_libraries(test-bh-client uvtls)

####

add_executable(test-bh-server src/test-bh-server.c)

target_include_directories(test-bh-server PRIVATE include)
target_include_directories(test-bh-server PRIVATE src)

target_link_libraries(test-bh-server uvtls)

####

add_executable(test-ring-buf src/test-ring-buf.c src/ring-buf.c)

target_include_directories(test-ring-buf PRIVATE include)
target_include_directories(test-ring-buf PRIVATE src)
