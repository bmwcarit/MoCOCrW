cmake_minimum_required(VERSION 3.5)

include(CTest)                      # Enable test target in Makefile
include(GNUInstallDirs)             # For standard Linux include directories
include(CMakePackageConfigHelpers)  # For packaging

set(SECURITY_COMPILER_FLAGS
    # Create canaries to protect RIP/RBP from stack overflows
    -fstack-protector-strong
)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Note that '-pie' needs to be specified as a linker flag to every executable
# individually, to ensure it has ASLR enabled on .text, .data, etc.
if(CMAKE_EXECUTABLE_FORMAT STREQUAL "ELF")
# Enable relro and BIND_NOW only if we gnerate ELF binaries
set(CMAKE_EXE_LINKER_FLAGS
    # Enforce non-executable stack and read only relocations
    "${CMAKE_EXE_LINKER_FLAGS} -z noexecstack -z relro -z now"
)
endif()

# Default compiler flags
set(CMAKE_CXX_STANDARD 14)
set(CXX_STANDARD_REQUIRED ON)

add_compile_options(
    -Wall -Wextra -pedantic
    ${SECURITY_COMPILER_FLAGS}
    "$<$<CONFIG:Debug>:-ggdb;-O0>"
)

# CMake modules provided by the project
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/cmake/)

# Code coverage flags
if(CMAKE_BUILD_TYPE STREQUAL Coverage)
    option(BUILD_TESTING "Build tests for all components" ON)

    set(COVERAGE_BASE_DIRS
        ${CMAKE_CURRENT_SOURCE_DIR}/src
    )

    find_package(Coverage REQUIRED)
endif()

if(CMAKE_BUILD_TYPE STREQUAL ASAN)
    include(AddressSanitizerTarget)
endif()
if(CMAKE_BUILD_TYPE STREQUAL UBSAN)
    include(UBSanitizerTarget)
endif()
if(CMAKE_BUILD_TYPE STREQUAL TSAN)
    include(ThreadSanitizerTarget)
endif()

###############################################################################
# Documentation
###############################################################################

if(BUILD_DOCUMENTATION)
    find_package(Doxygen REQUIRED)
endif()

###############################################################################
# Post-build tasks
###############################################################################

if(BUILD_DOCUMENTATION)
    add_subdirectory(doc)
endif()

find_package(OpenSSL REQUIRED)
if(OPENSSL_FOUND)
    message(STATUS "Using OpenSSL ${OPENSSL_VERSION}")
endif()

find_package(Boost REQUIRED)

# Installation directories
set(MOCOCRW ${CMAKE_INSTALL_LIBDIR}/cmake)
set(MOCOCRW_INSTALL_LIBDIR ${CMAKE_INSTALL_LIBDIR})
set(MOCOCRW_INSTALL_BINDIR ${CMAKE_INSTALL_FULL_BINDIR})

set(MOCOCRW_PROJECT_ROOT ${CMAKE_CURRENT_SOURCE_DIR})
set(SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src)
#TODO set(DOC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/doc)
set(TEST_DIR ${CMAKE_CURRENT_SOURCE_DIR}/tests)
set(UTILS_DIR ${CMAKE_CURRENT_SOURCE_DIR}/utils)

# Enable all subprojects to find each other's include files
include_directories(${SRC_DIR})

add_subdirectory(${SRC_DIR})
add_subdirectory(${TEST_DIR})
