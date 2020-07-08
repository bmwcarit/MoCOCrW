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

endif()
