if(BUILD_EXAMPLES AND BUILD_TESTING)
    set(EXAMPLE_BINARY_DIR ${CMAKE_BINARY_DIR}/examples)
    add_test(
	NAME "ExampleTesting"
	COMMAND sh -c "MOCOCRW_EXAMPLE_BINARY_PATH=${EXAMPLE_BINARY_DIR} MOCOCRW_SRC_DIR=${EXAMPLE_DIR} /usr/bin/python3 -m unittest"
    )
    configure_file(common.py common.py COPYONLY)
    configure_file(test_ecies.py test_ecies.py COPYONLY)
    configure_file(test_rsa.py test_rsa.py COPYONLY)
    configure_file(test_sig.py test_sig.py COPYONLY)
    configure_file(test_hash.py test_hash.py COPYONLY)
    configure_file(test_aes.py test_aes.py COPYONLY)
    configure_file(test_key.py test_key.py COPYONLY)
    configure_file(test_ca_and_csr.py test_ca_and_csr.py COPYONLY)
endif()
