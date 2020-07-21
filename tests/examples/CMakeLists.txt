if(BUILD_EXAMPLES AND BUILD_TESTING)
    set(EXAMPLE_BINARY_DIR ${CMAKE_BINARY_DIR}/examples)
    add_test(
	NAME "ExampleTesting"
	COMMAND sh -c "MOCOCRW_EXAMPLE_BINARY_PATH=${EXAMPLE_BINARY_DIR} MOCOCRW_SRC_DIR=${EXAMPLE_DIR} /usr/bin/python3 -m unittest"
    )
    configure_file(common.py common.py COPYONLY)
    configure_file(test_ecies.py test_ecies.py COPYONLY)
endif()
