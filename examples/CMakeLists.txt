project(mococrw-examples)

if(BUILD_EXAMPLES)
    message(STATUS "Compiling examples")
    find_package(Boost COMPONENTS program_options REQUIRED)

    set(COMMON_EXAMPLE_HEADERS
	"common.h"
    )
endif()
