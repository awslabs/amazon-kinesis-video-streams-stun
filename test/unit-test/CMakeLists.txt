# Set the required version.
cmake_minimum_required( VERSION 3.13.0 )

# Set the unit-test project.
project( "STUN unit test"
         VERSION 1.0.0
         LANGUAGES C )

# Allow the project to be organized into folders.
set_property( GLOBAL PROPERTY USE_FOLDERS ON )

# Use C99.
set( CMAKE_C_STANDARD 99 )
set( CMAKE_C_STANDARD_REQUIRED ON )

# Do not allow in-source build.
if( ${PROJECT_SOURCE_DIR} STREQUAL ${PROJECT_BINARY_DIR} )
    message( FATAL_ERROR "In-source build is not allowed. Please build in a separate directory, such as ${PROJECT_SOURCE_DIR}/build." )
endif()

# Set global path variables.
get_filename_component( __MODULE_ROOT_DIR "${CMAKE_CURRENT_LIST_DIR}/../.." ABSOLUTE )
set( MODULE_ROOT_DIR ${__MODULE_ROOT_DIR} CACHE INTERNAL "STUN repository root." )

# Set the unit-test directory.
set( UNIT_TEST_DIR ${MODULE_ROOT_DIR}/test/unit-test CACHE INTERNAL "Unit-test directory." )

# Set the include directories.
string( APPEND GLOBAL_INCLUDES "-I ${MODULE_ROOT_DIR}/source/include")

# Configure options to always show in CMake GUI.
option( BUILD_CLONE_SUBMODULES
        "Set this to ON to automatically clone any required Git submodules. When OFF, submodules must be manually cloned."
        ON )

# Set output directories.
set( CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin )
set( CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib )
set( CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib )

# ===================================== Include the cmake configurations =================================================
message( STATUS ${CMAKE_BINARY_DIR} )

# Include filepaths for source and include.
include( ${MODULE_ROOT_DIR}/stunFilePaths.cmake )

# Target for Coverity analysis that builds the library.
add_library( coverity_analysis
             ${STUN_SOURCES}
             ${STUN_INCLUDE_PUBLIC_DIRS}
             ${MODULE_ROOT_DIR}/test/unit-test )

target_compile_definitions( coverity_analysis PUBLIC NDEBUG=1 )

#STUN public include path.
target_include_directories( coverity_analysis PUBLIC ${STUN_INCLUDE_PUBLIC_DIRS} ${MODULE_ROOT_DIR}/test/unit-test )

# ========================= Test Configuration ==============================
# Define a CMock resource path.
set( CMOCK_DIR ${MODULE_ROOT_DIR}/test/CMock CACHE INTERNAL "CMock library source directory." )

# Include CMock build configuration.
include( cmock_build.cmake )

# Check if the CMock source directory exists, and if not present, clone the submodule
# if BUILD_CLONE_SUBMODULES configuration is enabled.
if( NOT EXISTS ${CMOCK_DIR}/source )
    # Attempt to clone CMock.
    if( ${BUILD_CLONE_SUBMODULES} )
        clone_cmock()
    else()
        message( FATAL_ERROR "The required submodule CMock does not exist. Either clone it manually, or set BUILD_CLONE_SUBMODULES to 'ON' to automatically clone it during build." )
    endif()
endif()

# Use CTest utility for managing test runs. This has to be added BEFORE
# defining test targets with add_test()
enable_testing()

# Add build targets for CMock and Unit, required for unit testing.
add_cmock_targets()

# Add function to enable CMock based tests and coverage.
include( ${MODULE_ROOT_DIR}/test/unit-test/cmock/create_test.cmake )

# Include unit-test build configuration.
include( ${UNIT_TEST_DIR}/stun_serializer/ut.cmake )
include( ${UNIT_TEST_DIR}/stun_deserializer/ut.cmake )

#  ==================================== Coverage Analysis configuration ========================================
# Add a target for running coverage on tests.
add_custom_target( coverage
    COMMAND ${CMAKE_COMMAND} -DCMOCK_DIR=${CMOCK_DIR}
    -P ${MODULE_ROOT_DIR}/test/unit-test/cmock/coverage.cmake
    DEPENDS cmock unity
    stun_serializer
    stun_deserializer
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
)

