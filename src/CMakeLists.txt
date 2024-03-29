project(MoCOCrW VERSION 0.1.0)

string(TOLOWER ${PROJECT_NAME} LIBRARY_NAME)

set(MoCOCrW_SOVERSION "4.0")
add_definitions(
    -DMOCOCRW_VERSION="${MoCOCrW_VERSION}"
    -DMOCOCRW_SOVERSION="${MoCOCrW_SOVERSION}"
)
set(MOCOCRW_INSTALL_INCLUDEDIR
    ${CMAKE_INSTALL_INCLUDEDIR}/MoCOCrW-${MoCOCrW_SOVERSION}
)

# Before you add anything here:
set(LIBRARY_SOURCES
    asn1time.cpp
    asymmetric_crypto_ctx.cpp
    basic_constraints.cpp
    bio.cpp
    ca.cpp
    crl.cpp
    csr.cpp
    distinguished_name.cpp
    ecies.cpp
    hash.cpp
    kdf.cpp
    key.cpp
    key_usage.cpp
    mac.cpp
    openssl_lib.cpp
    openssl_wrap.cpp
    subject_key_identifier.cpp
    symmetric_crypto.cpp
    symmetric_memory.cpp
    padding_mode.cpp
    util.cpp
    x509.cpp
)

# Add additional source files if HSM features are enabled.
if(MOCOCRW_HSM_ENABLED)
  set(LIBRARY_SOURCES
      ${LIBRARY_SOURCES}
      hsm.cpp
  )
endif()

if(MOCOCRW_DILITHIUM_ENABLED)
    set(LIBRARY_SOURCES
        ${LIBRARY_SOURCES}
        dilithium.cpp
    )
endif()

# Set up configuration header for optional features.
configure_file(${MOCOCRW_PROJECT_ROOT}/cmake/in/MoCOCrWConfig.h.in ${MOCOCRW_INCLUDE_CONFIG_DIR}/mococrw/config.h)

set(LIBRARY_PUBLIC_HEADERS
    ${MOCOCRW_INCLUDE_CONFIG_DIR}/mococrw/config.h
    mococrw/asn1time.h
    mococrw/asymmetric_crypto_ctx.h
    mococrw/basic_constraints.h
    mococrw/bio.h
    mococrw/ca.h
    mococrw/crl.h
    mococrw/csr.h
    mococrw/distinguished_name.h
    mococrw/ecies.h
    mococrw/error.h
    mococrw/extension.h
    mococrw/hash.h
    mococrw/kdf.h
    mococrw/key.h
    mococrw/key_usage.h
    mococrw/mac.h
    mococrw/openssl_lib.h
    mococrw/openssl_wrap.h
    mococrw/padding_mode.h
    mococrw/sign_params.h
    mococrw/subject_key_identifier.h
    mococrw/symmetric_crypto.h
    mococrw/util.h
    mococrw/x509.h
)

# Add additional header files if HSM features are enabled.
if(MOCOCRW_HSM_ENABLED)
  set(LIBRARY_PUBLIC_HEADERS
      ${LIBRARY_PUBLIC_HEADERS}
      mococrw/hsm.h
  )
endif()

if(MOCOCRW_DILITHIUM_ENABLED)
    set(LIBRARY_PUBLIC_HEADERS
        ${LIBRARY_PUBLIC_HEADERS}
        mococrw/dilithium.h
    )
endif()

add_library(${LIBRARY_NAME} SHARED ${LIBRARY_SOURCES} ${LIBRARY_PUBLIC_HEADERS})
add_library(${PROJECT_NAME}::${LIBRARY_NAME} ALIAS ${LIBRARY_NAME})
target_link_libraries(${LIBRARY_NAME} PUBLIC OpenSSL::Crypto OpenSSL::SSL Boost::boost)

if(MOCOCRW_DILITHIUM_ENABLED)
    target_link_libraries(${LIBRARY_NAME} PRIVATE dilithium2_ref dilithium3_ref dilithium5_ref aes256ctr_ref fips202_ref)
endif()

target_include_directories(${LIBRARY_NAME} INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    $<BUILD_INTERFACE:${MOCOCRW_INCLUDE_CONFIG_DIR}>
    $<INSTALL_INTERFACE:${MOCOCRW_INSTALL_INCLUDEDIR}>
)
set_target_properties(${LIBRARY_NAME} PROPERTIES
    VERSION ${MoCOCrW_VERSION}
    SOVERSION ${MoCOCrW_SOVERSION}
)

set(_project_install_includedir ${CMAKE_CURRENT_SOURCE_DIR})
configure_package_config_file(
    ${MOCOCRW_PROJECT_ROOT}/cmake/MoCOCrWConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/MoCOCrWConfig.cmake
    INSTALL_DESTINATION ${CMAKE_CURRENT_BINARY_DIR}
    PATH_VARS MoCOCrW_SOVERSION _project_install_includedir
)
export(PACKAGE ${PROJECT_NAME})

export(TARGETS ${LIBRARY_NAME} NAMESPACE ${PROJECT_NAME}::
    FILE ${CMAKE_BINARY_DIR}/MoCOCrWTargets.cmake)

install(FILES ${LIBRARY_PUBLIC_HEADERS} DESTINATION ${MOCOCRW_INSTALL_INCLUDEDIR}/mococrw)

# Install library
install(
    TARGETS ${LIBRARY_NAME}
    EXPORT MoCOCrWTargets
    DESTINATION ${MOCOCRW_INSTALL_LIBDIR}
)

set(CONFIG_INSTALL_DIR
    ${MOCOCRW_INSTALL_LIBDIR}/cmake/MoCOCrW-${MoCOCrW_SOVERSION}
)
set(_project_install_includedir ${MOCOCRW_INSTALL_INCLUDEDIR})
configure_package_config_file(
    ${MOCOCRW_PROJECT_ROOT}/cmake/MoCOCrWConfig.cmake.in
    ${CMAKE_BINARY_DIR}/MoCOCrWConfig.cmake
    INSTALL_DESTINATION ${CONFIG_INSTALL_DIR}
    PATH_VARS MoCOCrW_SOVERSION _project_install_includedir
)

write_basic_package_version_file(
    ${CMAKE_BINARY_DIR}/MoCOCrWConfigVersion.cmake
    VERSION ${MoCOCrW_VERSION}
    COMPATIBILITY SameMajorVersion
)

install(
    FILES ${CMAKE_BINARY_DIR}/MoCOCrWConfig.cmake
          ${CMAKE_BINARY_DIR}/MoCOCrWConfigVersion.cmake
    DESTINATION ${CONFIG_INSTALL_DIR}
)

# Configure and install exported targets configuration file.
install(
    EXPORT MoCOCrWTargets FILE MoCOCrWTargets.cmake NAMESPACE ${PROJECT_NAME}::
    DESTINATION ${CONFIG_INSTALL_DIR}
)
