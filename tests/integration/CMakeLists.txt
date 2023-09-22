cmake_minimum_required(VERSION 3.3.1)

project(MoCOCrWIntegrationTests)

find_package(MoCOCrW)

set(CMAKE_CXX_STANDARD 14)
set(CXX_STANDARD_REQUIRED ON)

add_compile_options(
    -Wfatal-errors
)

if(MOCOCRW_HSM_ENABLED)
    add_executable(hsm-integration-test hsm-integration-test.cpp)
    target_link_libraries(hsm-integration-test PRIVATE MoCOCrW::mococrw)
    target_compile_definitions(hsm-integration-test PRIVATE HSM_ENABLED)
    # libp11 writes to stderr on unsuccessful key loading. Pipe it to devnull
    add_test(
        NAME HsmIntegrationTest
        COMMAND sh -c "${CMAKE_CURRENT_BINARY_DIR}/hsm-integration-test-wrapper.sh > /tmp/hsm-int-test.log"
    )

    # Copy the shell script for test execution and set the current source dir using sed
    add_custom_command(
        TARGET hsm-integration-test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy
                                    ${CMAKE_CURRENT_SOURCE_DIR}/hsm-integration-test-wrapper.sh
                                    ${CMAKE_CURRENT_BINARY_DIR}/hsm-integration-test-wrapper.sh
        COMMAND sed -i -e \"s;@CMAKE_CURRENT_SOURCE_DIR@;${CMAKE_CURRENT_SOURCE_DIR};g\"
                            ${CMAKE_CURRENT_BINARY_DIR}/hsm-integration-test-wrapper.sh
    )

endif()

