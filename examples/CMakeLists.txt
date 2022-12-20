add_executable(aes-example aes-example.cpp)
target_link_libraries(aes-example PUBLIC MoCOCrW::mococrw)
add_test(
    NAME aesExample
    COMMAND aes-example
)

add_executable(ca-csr-example ca-csr-example.cpp)
target_link_libraries(ca-csr-example PUBLIC MoCOCrW::mococrw)
add_test(
    NAME caCsrExample
    COMMAND ca-csr-example
)

add_executable(ecies-example ecies-example.cpp)
target_link_libraries(ecies-example PUBLIC MoCOCrW::mococrw)
add_test(
    NAME eciesExample
    COMMAND ecies-example
)

add_executable(hash-example hash-example.cpp)
target_link_libraries(hash-example PUBLIC MoCOCrW::mococrw)
add_test(
    NAME hashExample
    COMMAND hash-example
)

# Only build HSM example if HSM features have been enabled.
#
# TODO: Make the HSM flag be an imported variable so users
# can easily determine its status.
if(HSM_ENABLED)
    add_executable(hsm-example hsm-example.cpp)
    target_link_libraries(hsm-example PUBLIC MoCOCrW::mococrw)
    target_compile_definitions(hsm-example PUBLIC HSM_ENABLED)

    add_test(
        NAME hsmExample
        COMMAND hsm-example
    )
else()
    message(WARNING "Skipping HSM example, as HSM features are disabled.")
endif()

add_executable(kdf-example kdf-example.cpp)
target_link_libraries(kdf-example PUBLIC MoCOCrW::mococrw)
add_test(
    NAME kdfExample
    COMMAND kdf-example
)

add_executable(key-example key-example.cpp)
target_link_libraries(key-example PUBLIC MoCOCrW::mococrw)
add_test(
    NAME keyExample
    COMMAND key-example
)

add_executable(mac-example mac-example.cpp)
target_link_libraries(mac-example PUBLIC MoCOCrW::mococrw)
add_test(
    NAME macExample
    COMMAND mac-example
)

add_executable(rsa-example rsa-example.cpp)
target_link_libraries(rsa-example PUBLIC MoCOCrW::mococrw)
add_test(
    NAME rsaExample
    COMMAND rsa-example
)

add_executable(sig-example sig-example.cpp)
target_link_libraries(sig-example PUBLIC MoCOCrW::mococrw)
if(DILITHIUM_ENABLED)
    target_compile_definitions(sig-example PUBLIC DILITHIUM_ENABLED)
endif()
add_test(
    NAME sigExample
    COMMAND sig-example
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/dilithium-keys"
)

add_executable(cert-validation cert-validation.cpp)
target_link_libraries(cert-validation PUBLIC MoCOCrW::mococrw)
add_test(
    NAME certValidation
    COMMAND cert-validation
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/test-certs"
)
