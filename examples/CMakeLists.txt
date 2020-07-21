project(mococrw-examples)

if(BUILD_EXAMPLES)
    message(STATUS "Compiling examples")
    find_package(Boost COMPONENTS program_options REQUIRED)

    set(COMMON_EXAMPLE_HEADERS
	"common.h"
    )
    add_executable(mococrw-ecies
	"ecies_example.cpp"
	"ecies_main.cpp"
	"ecies_example.h"
	"${COMMON_EXAMPLE_HEADERS}"
    )
    target_link_libraries(mococrw-ecies
	PUBLIC MoCOCrW::mococrw Boost::program_options
    )
    add_executable(mococrw-rsa
	"rsa_example.cpp"
	"rsa_main.cpp"
	"rsa_example.h"
	"${COMMON_EXAMPLE_HEADERS}"
    )
    target_link_libraries(mococrw-rsa
	PUBLIC MoCOCrW::mococrw Boost::program_options
    )
    add_executable(mococrw-sig
	"sig_example.cpp"
	"sig_example.h"
	"sig_main.cpp"
	"${COMMON_EXAMPLE_HEADERS}"
    )
    target_link_libraries(mococrw-sig
	PUBLIC MoCOCrW::mococrw Boost::program_options
    )
    add_executable(mococrw-hash
	"hash_example.cpp"
	"hash_example.h"
	"hash_main.cpp"
	"${COMMON_EXAMPLE_HEADERS}"
    )
    target_link_libraries(mococrw-hash
	PUBLIC MoCOCrW::mococrw Boost::program_options
    )
    add_executable(mococrw-aes
	"aes_example.cpp"
	"aes_example.h"
	"aes_main.cpp"
	"${COMMON_EXAMPLE_HEADERS}"
    )
    target_link_libraries(mococrw-aes
	PUBLIC MoCOCrW::mococrw Boost::program_options
    )
    add_executable(mococrw-key
	"key_example.cpp"
	"key_example.h"
	"key_main.cpp"
	"${COMMON_EXAMPLE_HEADERS}"
    )
    target_link_libraries(mococrw-key
	PUBLIC MoCOCrW::mococrw Boost::program_options
    )
    add_executable(mococrw-ca
	"ca_example.cpp"
	"ca_example.h"
	"ca_main.cpp"
	"${COMMON_EXAMPLE_HEADERS}"
    )
    target_link_libraries(mococrw-ca
	PUBLIC MoCOCrW::mococrw Boost::program_options
    )
    add_executable(mococrw-csr
	"csr_example.cpp"
	"csr_example.h"
	"csr_main.cpp"
	"${COMMON_EXAMPLE_HEADERS}"
    )
    target_link_libraries(mococrw-csr
	PUBLIC MoCOCrW::mococrw Boost::program_options
    )
    add_executable(mococrw-kdf
	"kdf_example.cpp"
	"kdf_example.h"
	"kdf_main.cpp"
	"${COMMON_EXAMPLE_HEADERS}"
    )
    target_link_libraries(mococrw-kdf
	PUBLIC MoCOCrW::mococrw Boost::program_options
    )
endif()
