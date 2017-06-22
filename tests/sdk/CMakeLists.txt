cmake_minimum_required(VERSION 3.3.1)

project(MoCOCrWTest)

find_package(MoCOCrW)

set(CMAKE_CXX_STANDARD 14)
set(CXX_STANDARD_REQUIRED ON)

add_compile_options(
    -Wall -Wextra -pedantic
    ${SECURITY_COMPILER_FLAGS}
    "$<$<CONFIG:Debug>:-ggdb;-O0>"
)

add_executable(MoCOCrWTest main.cpp)

target_link_libraries(MoCOCrWTest
    PRIVATE MoCOCrW::mococrw
)
