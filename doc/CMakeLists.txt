###############################################################################
# Doxygen documentation
###############################################################################

# Doxygen documentation mutual exclusion between tests and source code
if(BUILD_DOCUMENTATION)

    set(DOC_SOURCE_DIRS "${PROJECT_SOURCE_DIR}/src")
    set(DOC_EXAMPLE_DIR "${PROJECT_SOURCE_DIR}/doc/examples")
    set(MAIN_PAGE_FILE "${PROJECT_SOURCE_DIR}/README.md")
    set(GEN_DOC_AUTOLINK_SUPPORT  "YES")
    set(GEN_DOC_ENABLED_SECTIONS  "MainPageEnabled")
    set(GEN_DOC_LAYOUT_FILE       "")
    set(GEN_DOC_GENERATE_TREEVIEW "YES")
    set(GEN_DOC_SEARCHENGINE      "YES")
    set(GEN_DOC_STRIP_FROM_PATH   "${PROJECT_SOURCE_DIR}")


    # Set doxygen configuration for Api documentation
    set(GEN_DOC_OUTPUT_DIRECTORY  "${CMAKE_BINARY_DIR}/doc")
    set(GEN_DOC_DIR               "${CMAKE_BINARY_DIR}/doc")


    configure_file(${CMAKE_SOURCE_DIR}/cmake/Doxyfile.in ${CMAKE_BINARY_DIR}/doc/Doxyfile @ONLY)

    # Add a target to generate API documentation with Doxygen ('make doc')
    add_custom_target(doc
            /bin/sh -c "DOXYGEN_EXECUTABLE=${DOXYGEN_EXECUTABLE} '${CMAKE_CURRENT_SOURCE_DIR}/doxygen.sh' '${GEN_DOC_OUTPUT_DIRECTORY}/Doxyfile'"
            WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/doc
            COMMENT "Generating API documentation with Doxygen" VERBATIM
            SOURCES ${DOXYGEN_FILES}
            )

    file(MAKE_DIRECTORY ${GEN_DOC_OUTPUT_DIRECTORY})

    install(
            DIRECTORY ${GEN_DOC_OUTPUT_DIRECTORY}
            DESTINATION ${GEN_DOC_DIR}
    )

endif()



