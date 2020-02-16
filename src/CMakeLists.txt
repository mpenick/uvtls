add_library(uvtls uvtls-openssl.c uvtls-common.c ring-buf.c curl-hostcheck.c)

set_target_properties(uvtls PROPERTIES VERSION ${PROJECT_VERSION})
set_target_properties(uvtls PROPERTIES SOVERSION 0)
set_target_properties(uvtls PROPERTIES PUBLIC_HEADER include/uvtls.h)

target_include_directories(uvtls PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
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
