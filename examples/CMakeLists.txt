add_executable(http-client http-client.c)
add_dependencies(http-client uvtls)
target_include_directories(http-client PRIVATE ${INCLUDE_DIRS})
target_link_libraries(http-client uvtls ${LIBRARIES})

add_executable(echo-client echo-client.c)
add_dependencies(echo-client uvtls)
target_include_directories(echo-client PRIVATE ${INCLUDE_DIRS})
target_link_libraries(echo-client uvtls ${LIBRARIES})

add_executable(echo-server echo-server.c)
add_dependencies(echo-server uvtls)
target_include_directories(echo-server PRIVATE ${INCLUDE_DIRS})
target_link_libraries(echo-server uvtls ${LIBRARIES})
