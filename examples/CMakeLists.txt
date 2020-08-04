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
add_test(
    NAME sigExample
    COMMAND sig-example
)
