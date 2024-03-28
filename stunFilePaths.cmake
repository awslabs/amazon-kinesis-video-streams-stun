# This file is to add source files and include directories
# into variables so that it can be reused from different repositories
# in their Cmake based build system by including this file.

# STUN library source files.
set( STUN_SOURCES
     "${CMAKE_CURRENT_LIST_DIR}/source/stun_deserializer.c"
     "${CMAKE_CURRENT_LIST_DIR}/source/stun_serializer.c"
     "${CMAKE_CURRENT_LIST_DIR}/source/stun_endianness.c" )

# STUN library Public Include directories.
set( STUN_INCLUDE_PUBLIC_DIRS
     "${CMAKE_CURRENT_LIST_DIR}/source/include" )

# STUN library public include header files.
set( STUN_INCLUDE_PUBLIC_FILES
     "source/include/stun_data_types.h"
     "source/include/stun_endianness.h"
     "source/include/stun_deserializer.h"
     "source/include/stun_serializer.h" )
