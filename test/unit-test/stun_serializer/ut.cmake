
# Include filepaths for source and include.
include( ${MODULE_ROOT_DIR}/stunFilePaths.cmake )

# ====================  Define your project name (edit) ========================
set( project_name "stun_serializer" )

message( STATUS "${project_name}" )

# =====================  Create your mock here  (edit)  ========================

# List the files to mock here.
list(APPEND mock_list
            "${MODULE_ROOT_DIR}/source/include/stun_serializer.h"
            "${MODULE_ROOT_DIR}/source/include/stun_data_types.h"
            "${MODULE_ROOT_DIR}/source/include/stun_endianness.h"
        )
# List the directories your mocks need.
list(APPEND mock_include_list
            ${STUN_INCLUDE_PUBLIC_DIRS}
            ${MODULE_ROOT_DIR}/test/unit-test
        )

# List the definitions of your mocks to control what to be included.
list(APPEND mock_define_list
            ""
       )

# ================= Create the library under test here (edit) ==================

# List the files you would like to test here.
list(APPEND real_source_files
            ${MODULE_ROOT_DIR}/source/stun_serializer.c
            ${MODULE_ROOT_DIR}/source/stun_endianness.c
        )
# List the directories the module under test includes.
list(APPEND real_include_directories
            ${STUN_INCLUDE_PUBLIC_DIRS}
            ${MODULE_ROOT_DIR}/test/unit-test
            ${CMOCK_DIR}/vendor/unity/src
        )

# =====================  Create UnitTest Code here (edit)  =====================

# list the directories your test needs to include.
list(APPEND test_include_directories
            ${CMOCK_DIR}/vendor/unity/src
            ${STUN_INCLUDE_PUBLIC_DIRS}
            ${MODULE_ROOT_DIR}/test/unit-test
        )

# =============================  (end edit)  ===================================

set(mock_name "${project_name}_mock")
set(real_name "${project_name}_real")

create_mock_list(${mock_name}
                "${mock_list}"
                "${MODULE_ROOT_DIR}/test/unit-test/cmock/project.yml"
                "${mock_include_list}"
                "${mock_define_list}"
        )

create_real_library(${real_name}
                    "${real_source_files}"
                    "${real_include_directories}"
                    "${mock_name}"
        )

list(APPEND utest_link_list
            lib${real_name}.a
        )

list(APPEND utest_dep_list
            ${real_name}
        )

set(utest_name "${project_name}_utest")
set(utest_source "${project_name}/${project_name}_utest.c")

create_test(${utest_name}
            ${utest_source}
            "${utest_link_list}"
            "${utest_dep_list}"
            "${test_include_directories}"
        )

        