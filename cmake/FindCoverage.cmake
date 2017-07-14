# - FindCoverage
# Find coverage tools from the lcov package and generate coverage target.
#
# Configuration:
#  COVERAGE_DIR             - Working directory where output is generated to
#                             download the sources to.
#  COVERAGE_BASE_DIRS       - List of LCOV base directories (defaults to ${CMAKE_SOURCE_DIR}/src).
#  COVERAGE_EXCLUDES        - List of additional exclude patterns.
#  COVERAGE_BRANCH_COVERAGE - Generate branch coverage.
#
# This module defines the following variables:
#  LCOV_FOUND          - If lcov is available
#  LCOV_EXECUTABLE     - The lcov executable
#  GENINFO_EXECUTABLE  - The geninfo executable (called by lcov)
#  GENHTML_EXECUTABLE  - The genhtml executable
#

# Coverage build type
set(CMAKE_CXX_FLAGS_COVERAGE "-g -O0 -fno-default-inline -fno-inline --coverage" CACHE STRING
    "Flags used by the C++ compiler during coverage builds." FORCE
)
set(CMAKE_C_FLAGS_COVERAGE "-g -O0 -fno-default-inline -fno-inline --coverage" CACHE STRING
    "Flags used by the C compiler during coverage builds." FORCE
)
set(CMAKE_EXE_LINKER_FLAGS_COVERAGE "--coverage" CACHE STRING
    "Flags used for linking binaries during coverage builds." FORCE
)
set(CMAKE_SHARED_LINKER_FLAGS_COVERAGE "--coverage" CACHE STRING
    "Flags used by the shared libraries linker during coverage builds." FORCE
)
mark_as_advanced(
    CMAKE_CXX_FLAGS_COVERAGE CMAKE_C_FLAGS_COVERAGE CMAKE_EXE_LINKER_FLAGS_COVERAGE
    CMAKE_SHARED_LINKER_FLAGS_COVERAGE CMAKE_STATIC_LINKER_FLAGS_COVERAGE
)

find_program(LCOV_EXECUTABLE lcov)
find_program(GENINFO_EXECUTABLE geninfo)
find_program(GENHTML_EXECUTABLE genhtml)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(LCOV
    REQUIRED_VARS LCOV_EXECUTABLE GENINFO_EXECUTABLE GENHTML_EXECUTABLE
)
mark_as_advanced(LCOV_EXECUTABLE GENINFO_EXECUTABLE GENHTML_EXECUTABLE)

if(NOT LCOV_FOUND)
    return()
endif()

# Set default directories.
if(NOT COVERAGE_DIR)
    set(COVERAGE_DIR ${CMAKE_CURRENT_BINARY_DIR}/coverage)
endif()

if(NOT COVERAGE_BASE_DIRS)
    set(COVERAGE_BASE_DIRS ${CMAKE_SOURCE_DIR}/src)
endif()
foreach(_coverage_dir IN LISTS COVERAGE_BASE_DIRS)
    list(APPEND _coverage_base_dirs --directory ${_coverage_dir})
endforeach()
unset(_coverage_dir)

if(NOT COVERAGE_EXCLUDES)
    set(COVERAGE_EXCLUDES)
endif()

if(COVERAGE_BRANCH_COVERAGE)
    set(_coverage_enable_branch 1)
else()
    set(_coverage_enable_branch 0)
endif()

# Add coverage target.
add_custom_target(coverage
    COMMAND ${CMAKE_COMMAND} -E make_directory ${COVERAGE_DIR}

    # Compile sources first. (It is not possible to depend on a built-in target such as 'all':
    # https://cmake.org/Bug/view.php?id=8438)
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}

    # In order to get coverage for files that are not executed in any test, lcov has to be called
    # with --capture --initial before the tests are executed. This base needs to be combined with
    # the output of the --capture call after the tests.

    COMMAND ${LCOV_EXECUTABLE} --zerocounters --directory ${CMAKE_BINARY_DIR} --quiet
    COMMAND ${LCOV_EXECUTABLE} --capture --initial --no-external --quiet
                               --directory ${CMAKE_BINARY_DIR}
                               ${_coverage_base_dirs}
                               --output-file ${COVERAGE_DIR}/${PROJECT_NAME}.coverage_base.info

    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target test || true

    COMMAND ${LCOV_EXECUTABLE} --capture --no-external --quiet
                               --directory ${CMAKE_BINARY_DIR}
                               --output-file ${COVERAGE_DIR}/${PROJECT_NAME}.coverage_test.info
                               ${_coverage_base_dirs}
                               --rc lcov_branch_coverage=${_coverage_enable_branch}

    COMMAND ${LCOV_EXECUTABLE} --add-tracefile ${COVERAGE_DIR}/${PROJECT_NAME}.coverage_base.info
                               --add-tracefile ${COVERAGE_DIR}/${PROJECT_NAME}.coverage_test.info
                               --output-file ${COVERAGE_DIR}/${PROJECT_NAME}.coverage.info
                               --quiet
                               --rc lcov_branch_coverage=${_coverage_enable_branch}

    COMMAND ${LCOV_EXECUTABLE} --remove ${COVERAGE_DIR}/${PROJECT_NAME}.coverage.info
                               ${CMAKE_BINARY_DIR}/* ${COVERAGE_EXCLUDES}
                               --output-file ${COVERAGE_DIR}/${PROJECT_NAME}.coverage.info
                               --quiet
                               --rc lcov_branch_coverage=${_coverage_enable_branch}

    COMMAND ${GENHTML_EXECUTABLE} ${COVERAGE_DIR}/${PROJECT_NAME}.coverage.info
                                  --output-directory ${COVERAGE_DIR}/html
                                  --show-details --legend --highlight --demangle-cpp
                                  --rc lcov_branch_coverage=${_coverage_enable_branch}

    COMMAND ${CMAKE_COMMAND} -E echo "Coverage report: file://${COVERAGE_DIR}/html/index.html"
    WORKING_DIRECTORY ${coverage_dir}
    VERBATIM
    COMMENT "Generate code coverage"
)

unset(_coverage_enable_branch)
unset(_coverage_base_dirs)
