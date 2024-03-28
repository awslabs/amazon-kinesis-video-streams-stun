cmake_minimum_required(VERSION 3.6.3)
project(kvsstun C)

include(stunFilePaths.cmake)

add_library(kvsstun ${STUN_SOURCES})

target_include_directories(kvsstun PUBLIC
                           ${STUN_INCLUDE_PUBLIC_DIRS})

# install header files
install(
    FILES ${STUN_INCLUDE_PUBLIC_FILES}
    DESTINATION include/kvsstun)

# install STUN library
install(
    TARGETS kvsstun
    ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
