project(mococrw-examples)

if(BUILD_EXAMPLES)
    message(STATUS "Compiling examples")
    set(EXAMPLE_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR})
    FIND_PACKAGE(Boost COMPONENTS program_options REQUIRED)

    include_directories("${UTILS_DIR}")

    set(COMMON_EXAMPLE_HEADERS
	"${UTILS_DIR}/IOUtils.h"
	"${UTILS_DIR}/parsingUtils.h"
	"${EXAMPLE_SRC_DIR}/common.h"
    )
    set(COMMON_EXAMPLE_SRC
	"${UTILS_DIR}/parsingUtils.cpp"
    )

    add_executable(mococrw-ecies
	"${EXAMPLE_SRC_DIR}/ecies_example.cpp"
	"${COMMON_EXAMPLE_HEADERS}"
	"${COMMON_EXAMPLE_SRC}"
    )
    target_link_libraries(mococrw-ecies
	PUBLIC MoCOCrW::mococrw ${Boost_LIBRARIES}
    )

    add_executable(mococrw-rsa
	"${EXAMPLE_SRC_DIR}/rsa_example.cpp"
	"${COMMON_EXAMPLE_HEADERS}"
	"${COMMON_EXAMPLE_SRC}"
    )
    target_link_libraries(mococrw-rsa
	PUBLIC MoCOCrW::mococrw ${Boost_LIBRARIES}
    )

    add_executable(mococrw-dsa
	"${EXAMPLE_SRC_DIR}/dsa_example.cpp"
	"${COMMON_EXAMPLE_HEADERS}"
	"${COMMON_EXAMPLE_SRC}"
    )
    target_link_libraries(mococrw-dsa
	PUBLIC MoCOCrW::mococrw ${Boost_LIBRARIES}
    )
    add_executable(mococrw-hash
	"${EXAMPLE_SRC_DIR}/hash_example.cpp"
	"${COMMON_EXAMPLE_HEADERS}"
	"${COMMON_EXAMPLE_SRC}"
    )
    target_link_libraries(mococrw-hash
	PUBLIC MoCOCrW::mococrw ${Boost_LIBRARIES}
    )
    add_executable(mococrw-aes
	"${EXAMPLE_SRC_DIR}/aes_example.cpp"
	"${COMMON_EXAMPLE_HEADERS}"
	"${COMMON_EXAMPLE_SRC}"
    )
    target_link_libraries(mococrw-aes
	PUBLIC MoCOCrW::mococrw ${Boost_LIBRARIES}
    )
    add_executable(mococrw-key
	"${EXAMPLE_SRC_DIR}/key_example.cpp"
	"${COMMON_EXAMPLE_HEADERS}"
	"${COMMON_EXAMPLE_SRC}"
    )
    target_link_libraries(mococrw-key
	PUBLIC MoCOCrW::mococrw ${Boost_LIBRARIES}
    )
    add_executable(mococrw-ca
	"${EXAMPLE_SRC_DIR}/ca_example.cpp"
	"${COMMON_EXAMPLE_HEADERS}"
	"${COMMON_EXAMPLE_SRC}"
    )
    target_link_libraries(mococrw-ca
	PUBLIC MoCOCrW::mococrw ${Boost_LIBRARIES}
    )
endif()
