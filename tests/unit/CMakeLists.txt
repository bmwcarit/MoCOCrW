project(mococrw)

if(BUILD_TESTING) #set by Ctest. Also set in the integration build environment.
    if(NOT GMOCK_BOTH_LIBRARIES)
        find_path(GMOCK_SRC_DIR
            NAMES src/gmock-all.cc
            PATHS /usr/src/gmock /usr/src/googletest/googlemock
            NO_DEFAULT_PATH
            ONLY_CMAKE_FIND_ROOT_PATH)
        if(GMOCK_SRC_DIR)
            message(STATUS "Found GMock sources in ${GMOCK_SRC_DIR}")
            add_subdirectory("${GMOCK_SRC_DIR}" gmock)
            set(GMOCK_BOTH_LIBRARIES "gmock_main")
        else()
            message(FATAL_ERROR "GMock sources not found build -DBUILD_TESTING=On requested!")
        endif()
    endif()

    #TODO: clean this up
    set(LIB_SOURCES "${SRC_DIR}/openssl_wrap.cpp" "${SRC_DIR}/bio.cpp" "${SRC_DIR}/distinguished_name.cpp")
    set(MOCK_SOURCES "openssl_lib_mock.cpp" ${LIB_SOURCES})
    set(REAL_SOURCES "${SRC_DIR}/openssl_lib.cpp" ${LIB_SOURCES})

    find_package(Threads)

    add_executable(openssltest test_opensslwrapper.cpp ${MOCK_SOURCES})

    add_executable(asn1timetests test_asn1time.cpp ${REAL_SOURCES})
    add_executable(keytests test_key.cpp ${REAL_SOURCES})
    add_executable(csrtests test_csr.cpp "${SRC_DIR}/key.cpp" ${REAL_SOURCES})
    add_executable(biotests test_bio.cpp ${REAL_SOURCES})
    add_executable(x509tests test_x509.cpp
                            "${SRC_DIR}/key.cpp"
                            "${SRC_DIR}/csr.cpp"
                            "${SRC_DIR}/asn1time.cpp"
                            "${SRC_DIR}/crl.cpp"
                             ${REAL_SOURCES})
    add_executable(crltests test_crl.cpp
                            "${SRC_DIR}/key.cpp"
                            "${SRC_DIR}/csr.cpp"
                            "${SRC_DIR}/asn1time.cpp"
                            "${SRC_DIR}/x509.cpp"
                            "${SRC_DIR}/crl.cpp"
                             ${REAL_SOURCES})
    add_executable(verificationtests test_verification.cpp
                            "${SRC_DIR}/key.cpp"
                            "${SRC_DIR}/csr.cpp"
                            "${SRC_DIR}/asn1time.cpp"
                            "${SRC_DIR}/x509.cpp"
                            "${SRC_DIR}/crl.cpp"
                             ${REAL_SOURCES})
    add_executable(dntests test_distinguished_name.cpp ${REAL_SOURCES})
    add_executable(catests   test_ca.cpp
                            "${SRC_DIR}/key.cpp"
                            "${SRC_DIR}/csr.cpp"
                            "${SRC_DIR}/ca.cpp"
                            "${SRC_DIR}/x509.cpp"
                            "${SRC_DIR}/key_usage.cpp"
                            "${SRC_DIR}/asn1time.cpp"
                            "${SRC_DIR}/basic_constraints.cpp"
                            "${SRC_DIR}/crl.cpp"
                             ${REAL_SOURCES})

    target_link_libraries(openssltest ${GMOCK_BOTH_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})

    target_link_libraries(asn1timetests ${GMOCK_BOTH_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT} ${OPENSSL_LIBRARIES})
    target_link_libraries(keytests ${GMOCK_BOTH_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT} ${OPENSSL_LIBRARIES})
    target_link_libraries(csrtests ${GMOCK_BOTH_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT} ${OPENSSL_LIBRARIES})
    target_link_libraries(biotests ${GMOCK_BOTH_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT} ${OPENSSL_LIBRARIES})
    target_link_libraries(x509tests ${GMOCK_BOTH_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT} ${OPENSSL_LIBRARIES})
    target_link_libraries(crltests ${GMOCK_BOTH_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT} ${OPENSSL_LIBRARIES})
    target_link_libraries(verificationtests ${GMOCK_BOTH_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT} ${OPENSSL_LIBRARIES})
    target_link_libraries(dntests ${GMOCK_BOTH_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT} ${OPENSSL_LIBRARIES})
    target_link_libraries(catests ${GMOCK_BOTH_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT} ${OPENSSL_LIBRARIES})

    add_test(OpenSSLTest openssltest)

    add_test(Asn1TimeTests asn1timetests)
    add_test(KeyTest keytests)
    add_test(CsrTests csrtests)
    add_test(
        NAME BioTests
        COMMAND biotests
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/test-certs"
    )
    add_test(DistinguishedNameTests dntests)
    add_test(
        NAME X509Tests
        COMMAND x509tests
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/test-certs"
    )
    add_test(
        NAME CRLTests
        COMMAND crltests
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/test-certs"
    )
    add_test(
        NAME VerificationTests
        COMMAND verificationtests
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/test-certs"
    )
    add_test(
        NAME CATests
        COMMAND catests
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/test-certs"
    )

    # Configure valgrind
    find_program(MEMORYCHECK_COMMAND NAMES valgrind)
    set(_ARGS "--leak-check=full --track-origins=yes")
    set(_ARGS "${_ARGS} --xml=yes --xml-file=valgrind_%p.xml")
    set(MEMORYCHECK_COMMAND_OPTIONS ${_ARGS})
    include(CTest)
endif()
