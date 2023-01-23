cmake_minimum_required(VERSION 3.3.1)

project(MoCOCrWIntegrationTests)

find_package(MoCOCrW)

set(CMAKE_CXX_STANDARD 14)
set(CXX_STANDARD_REQUIRED ON)

add_compile_options(
    -Wfatal-errors
)

if(HSM_ENABLED)
    add_executable(hsm-integration-test hsm-integration-test.cpp)
    target_link_libraries(hsm-integration-test PRIVATE MoCOCrW::mococrw)
    target_compile_definitions(hsm-integration-test PRIVATE HSM_ENABLED)
    add_test(
        NAME HsmIntegrationTest
        COMMAND hsm-integration-test
    )
endif()

