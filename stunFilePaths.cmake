# This file is to add source files and include directories
# into variables so that it can be reused from different repositories
# in their Cmake based build system by including this file.
#
# Files specific to the repository such as test runner, platform tests
# are not added to the variables.

# STUN library source files.
set( STUN_SOURCES
     "${CMAKE_CURRENT_LIST_DIR}/lib/source/stun_deserializer.c"
     "${CMAKE_CURRENT_LIST_DIR}/lib/source/stun_serializer.c"
     "${CMAKE_CURRENT_LIST_DIR}/lib/source/stun_endianness.c" )

# STUN library Public Include directories.
set( STUN_INCLUDE_PUBLIC_DIRS
     "${CMAKE_CURRENT_LIST_DIR}/lib/source/include" )