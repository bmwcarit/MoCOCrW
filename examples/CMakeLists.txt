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
endif()
