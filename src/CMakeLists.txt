project(MoCOCrW VERSION 0.1.0)

string(TOLOWER ${PROJECT_NAME} LIBRARY_NAME)

set(MoCOCrW_SOVERSION "1.0")
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
    hash.cpp
    key.cpp
    key_usage.cpp
    openssl_lib.cpp
    openssl_wrap.cpp
    subject_key_identifier.cpp
    padding_mode.cpp
    util.cpp
    x509.cpp
)

set(LIBRARY_PUBLIC_HEADERS
    mococrw/asn1time.h
    mococrw/asymmetric_crypto_ctx.h
    mococrw/basic_constraints.h
    mococrw/ca.h
    mococrw/crl.h
    mococrw/csr.h
    mococrw/distinguished_name.h
    mococrw/error.h
    mococrw/extension.h
    mococrw/hash.h
    mococrw/key.h
    mococrw/key_usage.h
    mococrw/openssl_lib.h
    mococrw/openssl_wrap.h
    mococrw/padding_mode.h
    mococrw/sign_params.h
    mococrw/subject_key_identifier.h
    mococrw/util.h
    mococrw/util.h
    mococrw/x509.h
)


add_library(${LIBRARY_NAME} SHARED ${LIBRARY_SOURCES})
add_library(${PROJECT_NAME}::${LIBRARY_NAME} ALIAS ${LIBRARY_NAME})
target_include_directories(${LIBRARY_NAME} PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/cwrap")
target_link_libraries(${LIBRARY_NAME} PUBLIC OpenSSL::Crypto OpenSSL::SSL Boost::boost)

target_include_directories(${LIBRARY_NAME} INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
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
