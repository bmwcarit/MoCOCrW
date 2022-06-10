# - FindLibP11
# Find the LibP11 Library.
#
# Configuration:
#  LIBP11_ROOT_DIR     - Root directory containing the installation of LibP11.
#                        Used as a hint to find the library.
#
# This module defines the following variables:
#  LIBP11_FOUND        - If LibP11 is available
#  LIBP11_INCLUDE_DIR  - The include directory of LibP11.
#  LIBP11_LIBRARY      - The LibP11 Library.
#
# This module defines the following `IMPORTED` targets:
#  LibP11::P11         - The LibP11 library.


set(_LIBP11_ROOT_HINTS
  HINTS
    ${LIBP11_ROOT_DIR}
)

find_path(LIBP11_INCLUDE_DIR
  NAMES
    libp11.h
    ${_LIBP11_ROOT_HINTS}
  PATH_SUFFIXES
    "include"
)

mark_as_advanced(LIBP11_INCLUDE_DIR)

find_library(LIBP11_LIBRARY
  NAMES
    p11
  NAMES_PER_DIR
    ${_LIBP11_ROOT_HINTS}
  PATH_SUFFIXES
    lib lib64
)

mark_as_advanced(LIBP11_LIBRARY)

find_package_handle_standard_args(LibP11
  REQUIRED_VARS
    LIBP11_LIBRARY
    LIBP11_INCLUDE_DIR
  FAIL_MESSAGE
    "LibP11 not found. Set LIBP11_ROOT_DIR path to provide hint."
)

if(LIBP11_FOUND)
  if(NOT TARGET LibP11::P11 AND EXISTS "${LIBP11_LIBRARY}")
    add_library(LibP11::P11 UNKNOWN IMPORTED)
    set_target_properties(LibP11::P11 PROPERTIES
      INTERFACE_INCLUDE_DIRECTORIES "${LIBP11_INCLUDE_DIR}")
    if(EXISTS "${LIBP11_LIBRARY}")
      set_target_properties(LibP11::P11 PROPERTIES
        IMPORTED_LINK_INTERFACE_LANGUAGES "C"
	IMPORTED_LOCATION "${LIBP11_LIBRARY}")
    endif()
  endif()
endif()

