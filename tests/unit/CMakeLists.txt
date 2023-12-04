project(mococrw)

if(BUILD_TESTING) #set by Ctest. Also set in the integration build environment.
    if(NOT GMOCK_BOTH_LIBRARIES)
        find_package(GTest REQUIRED) 
        set(GMOCK_BOTH_LIBRARIES GTest::gmock_main)
    endif()

    add_compile_options(
        -Wfatal-errors
    )

    #TODO: clean this up
    set(LIB_SOURCES "${SRC_DIR}/openssl_wrap.cpp" "${SRC_DIR}/bio.cpp" "${SRC_DIR}/distinguished_name.cpp")
    set(MOCK_SOURCES "openssl_lib_mock.cpp" ${LIB_SOURCES})
    set(REAL_SOURCES "${SRC_DIR}/openssl_lib.cpp" ${LIB_SOURCES})

    find_package(Threads)

    add_executable(openssltest test_opensslwrapper.cpp
                             ${MOCK_SOURCES})

    if(MOCOCRW_HSM_ENABLED)
        add_executable(hsmtest test_hsm.cpp
                            "${SRC_DIR}/key.cpp"
                            "${SRC_DIR}/util.cpp"
                             ${MOCK_SOURCES})
    endif()

    add_executable(asn1timetests test_asn1time.cpp ${REAL_SOURCES})
    add_executable(keytests test_key.cpp ${REAL_SOURCES})
    add_executable(csrtests test_csr.cpp "${SRC_DIR}/key.cpp" ${REAL_SOURCES})
    add_executable(biotests test_bio.cpp ${REAL_SOURCES})
    add_executable(hashtests test_hash.cpp ${REAL_SOURCES})
    add_executable(utiltests test_util.cpp ${REAL_SOURCES})
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
    add_executable(signaturetests test_signature.cpp
                            "${SRC_DIR}/key.cpp"
                            "${SRC_DIR}/csr.cpp"
                            "${SRC_DIR}/ca.cpp"
                            "${SRC_DIR}/x509.cpp"
                            "${SRC_DIR}/key_usage.cpp"
                            "${SRC_DIR}/asn1time.cpp"
                            "${SRC_DIR}/crl.cpp"
                            "${SRC_DIR}/hash.cpp"
                            "${SRC_DIR}/padding_mode.cpp"
                            ${REAL_SOURCES})
    add_executable(asymencryptiontests test_asymmetric_encryption.cpp
                            "${SRC_DIR}/key.cpp"
                            "${SRC_DIR}/csr.cpp"
                            "${SRC_DIR}/ca.cpp"
                            "${SRC_DIR}/x509.cpp"
                            "${SRC_DIR}/key_usage.cpp"
                            "${SRC_DIR}/asn1time.cpp"
                            "${SRC_DIR}/basic_constraints.cpp"
                            "${SRC_DIR}/crl.cpp"
                            "${SRC_DIR}/util.cpp"
                            "${SRC_DIR}/padding_mode.cpp"
                            "${SRC_DIR}/hash.cpp"
                            ${REAL_SOURCES})
    add_executable(rsa_padding_mode_tests test_padding_mode.cpp
                            "${SRC_DIR}/hash.cpp"
                            "${SRC_DIR}/key.cpp"
                            "${SRC_DIR}/x509.cpp"
                            "${SRC_DIR}/csr.cpp"
                            "${SRC_DIR}/crl.cpp"
                            "${SRC_DIR}/asn1time.cpp"
                            "${SRC_DIR}/padding_mode.cpp"
                            ${REAL_SOURCES})
    add_executable(symmencryptiontests test_symmetric_crypto.cpp
        "${SRC_DIR}/symmetric_crypto.cpp"
        "${SRC_DIR}/symmetric_memory.cpp"
        "${SRC_DIR}/util.cpp"
        ${REAL_SOURCES})
    add_executable(symmmemorytests test_symmetric_memory.cpp
        "${SRC_DIR}/symmetric_memory.cpp")

    add_executable(kdftests test_kdf.cpp
	"${SRC_DIR}/kdf.cpp"
	${REAL_SOURCES})

    add_executable(hmactests test_hmac.cpp
    	"${SRC_DIR}/mac.cpp"
    	"${SRC_DIR}/hash.cpp"
    	${REAL_SOURCES})

    add_executable(cmactests test_cmac.cpp
    	"${SRC_DIR}/mac.cpp"
    	"${SRC_DIR}/hash.cpp"
    	${REAL_SOURCES})

    add_executable(eciestests test_ecies.cpp
        "${SRC_DIR}/ecies.cpp"
        "${SRC_DIR}/key.cpp"
        "${SRC_DIR}/x509.cpp"
        "${SRC_DIR}/asn1time.cpp"
        "${SRC_DIR}/crl.cpp"
        "${SRC_DIR}/symmetric_crypto.cpp"
        "${SRC_DIR}/symmetric_memory.cpp"
        "${SRC_DIR}/util.cpp"
        "${SRC_DIR}/mac.cpp"
        "${SRC_DIR}/hash.cpp"
        "${SRC_DIR}/kdf.cpp"
        ${REAL_SOURCES})

    if(MOCOCRW_DILITHIUM_ENABLED)
        add_executable(dilithiumtests test_dilithium.cpp
            "${SRC_DIR}/asymmetric_crypto_ctx.cpp"
            "${SRC_DIR}/hash.cpp"
            "${SRC_DIR}/x509.cpp"
            "${SRC_DIR}/asn1time.cpp"
            "${SRC_DIR}/key.cpp"
            "${SRC_DIR}/crl.cpp"
            "${SRC_DIR}/util.cpp"
            ${REAL_SOURCES})
    endif()

    set(DEFAULT_LINK_LIBRARIES ${GMOCK_BOTH_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT} OpenSSL::Crypto OpenSSL::SSL Boost::boost)

    target_link_libraries(openssltest ${GMOCK_BOTH_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})
    # Cannot link to imported OpenSSL and leverage implicit include-dir-propagation, as openssltest uses mocks.
    target_include_directories(openssltest PUBLIC ${OPENSSL_INCLUDE_DIR})

    if(MOCOCRW_HSM_ENABLED)
        target_link_libraries(hsmtest ${GMOCK_BOTH_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})
        target_include_directories(hsmtest PUBLIC ${OPENSSL_INCLUDE_DIR})
    endif()

    if(MOCOCRW_DILITHIUM_ENABLED)
        set(DEFAULT_LINK_LIBRARIES ${DEFAULT_LINK_LIBRARIES} dilithium2_ref dilithium3_ref dilithium5_ref aes256ctr_ref fips202_ref)
        target_link_libraries(dilithiumtests ${DEFAULT_LINK_LIBRARIES})
    endif()

    target_link_libraries(asn1timetests ${DEFAULT_LINK_LIBRARIES})
    target_link_libraries(keytests ${DEFAULT_LINK_LIBRARIES})
    target_link_libraries(csrtests ${DEFAULT_LINK_LIBRARIES})
    target_link_libraries(biotests ${DEFAULT_LINK_LIBRARIES})
    target_link_libraries(hashtests ${DEFAULT_LINK_LIBRARIES})
    target_link_libraries(utiltests ${DEFAULT_LINK_LIBRARIES})
    target_link_libraries(x509tests ${DEFAULT_LINK_LIBRARIES})
    target_link_libraries(crltests ${DEFAULT_LINK_LIBRARIES})
    target_link_libraries(verificationtests ${DEFAULT_LINK_LIBRARIES})
    target_link_libraries(dntests ${DEFAULT_LINK_LIBRARIES})
    target_link_libraries(catests ${DEFAULT_LINK_LIBRARIES})
    target_link_libraries(signaturetests ${DEFAULT_LINK_LIBRARIES})
    target_link_libraries(asymencryptiontests ${DEFAULT_LINK_LIBRARIES})
    target_link_libraries(rsa_padding_mode_tests ${DEFAULT_LINK_LIBRARIES})
    target_link_libraries(symmencryptiontests ${DEFAULT_LINK_LIBRARIES})
    target_link_libraries(symmmemorytests
        ${GMOCK_BOTH_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT}  Boost::boost)
    target_link_libraries(kdftests ${DEFAULT_LINK_LIBRARIES})
    target_link_libraries(hmactests ${DEFAULT_LINK_LIBRARIES})
    target_link_libraries(cmactests ${DEFAULT_LINK_LIBRARIES})
    target_link_libraries(eciestests ${DEFAULT_LINK_LIBRARIES})

    add_test(
        NAME OpenSSLTest
        COMMAND openssltest
    )

    if(MOCOCRW_HSM_ENABLED)
        add_test(
            NAME HSMTest
            COMMAND hsmtest
        )
    endif()

    add_test(
        NAME Asn1TimeTests
        COMMAND asn1timetests
    )
    add_test(
        NAME HashTests
        COMMAND hashtests
    )
    add_test(
        NAME UtilTests
        COMMAND utiltests
    )
    add_test(
        NAME KeyTest
        COMMAND keytests
    )
    add_test(
        NAME CsrTests
        COMMAND csrtests
    )
    add_test(
        NAME BioTests
        COMMAND biotests
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/test-certs"
    )
    add_test(
        NAME DistinguishedNameTests
        COMMAND dntests
    )
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
    add_test(
        NAME SignatureTests
        COMMAND signaturetests
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/test-certs"
    )
    add_test(
        NAME AsymEncryptionTests
        COMMAND asymencryptiontests
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/test-certs"
    )
    add_test(
        NAME RSAPaddingModeTests
        COMMAND rsa_padding_mode_tests
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/test-certs"
    )
    add_test(
        NAME SymmetricCipherTest
        COMMAND symmencryptiontests
    )
    add_test(
        NAME SymmetricCipherMemoryModelTest
        COMMAND symmmemorytests
    )
    add_test(
	NAME KdfSchemesTest
	COMMAND kdftests
    )
    add_test(
        NAME HMacSchemesTest
	COMMAND hmactests
    )
    add_test(
        NAME CMacSchemesTest
	COMMAND cmactests
    )
    add_test(
	NAME EciesSchemesTest
	COMMAND eciestests
    )

    if(MOCOCRW_DILITHIUM_ENABLED)
        add_test(
            NAME DilithiumSignatureTests
            COMMAND dilithiumtests
            WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/dilithium-keys"
        )
    endif()

    # Configure valgrind
    find_program(MEMORYCHECK_COMMAND NAMES valgrind)
    set(_ARGS "--leak-check=full --track-origins=yes")
    set(_ARGS "${_ARGS} --xml=yes --xml-file=valgrind_%p.xml")
    set(MEMORYCHECK_COMMAND_OPTIONS ${_ARGS})
    include(CTest)
endif()
