cmake_minimum_required(VERSION 2.8.9)
INCLUDE(CPack)
set(CPACK_GENERATOR "ZIP")
SET(CPACK_BINARY_NSIS "OFF")
SET(CPACK_BINARY_ZIP "ON")
project (SecureFetch)


MESSAGE(STATUS "Looking for libunbound")
FIND_PATH(UNBOUND_INCLUDE_DIR
  NAMES unbound.h
  PATH_SUFFIXES include/ include/unbound/
  PATHS "${PROJECT_SOURCE_DIR}"
  ${UNBOUND_ROOT}
  $ENV{UNBOUND_ROOT}
  /usr/local/
  /usr/
)
find_library(UNBOUND_LIBRARIES unbound)




MESSAGE(STATUS "Looking for libLDNS")
find_path (LDNS_INCLUDE_DIR NAMES ldns/ldns.h)
mark_as_advanced(LDNS_INCLUDE_DIR)

find_library(LDNS_LIBRARY NAMES
  ldns
  libldns
  )
mark_as_advanced(LDNS_LIBRARY)

if(LDNS_INCLUDE_DIR)
  foreach(_ldns_version_header util.h)
    if(EXISTS "${LDNS_INCLUDE_DIR}/ldns/${_ldns_version_header}")
      file(STRINGS "${LDNS_INCLUDE_DIR}/ldns/${_ldns_version_header}" ldns_version_str REGEX "^#define[\t ]+LDNS_VERSION[\t ]+\".*\"")

      string(REGEX REPLACE "^#define[\t ]+LDNS_VERSION[\t ]+\"([^\"]*)\".*" "\\1" LDNS_VERSION_STRING "${ldns_version_str}")
      unset(ldns_version_str)
      break()
    endif()
  endforeach()
endif()

include(FindPackageHandleStandardArgs)

FIND_PACKAGE_HANDLE_STANDARD_ARGS(LDNS
                                  REQUIRED_VARS LDNS_LIBRARY LDNS_INCLUDE_DIR
                                  VERSION_VAR LDNS_VERSION_STRING)

if(LDNS_FOUND)
  set(LDNS_LIBRARIES ${LDNS_LIBRARY})
  set(LDNS_INCLUDE_DIRS ${LDNS_INCLUDE_DIR})
endif()


# Set library directories:
set ( PROJECT_LINK_LIBS "${LDNS_LIBRARY}" "${UNBOUND_LIBRARIES}" ssl crypto)

link_directories( ./lib/build usr/local/lib usr/lib "${UNBOUND_LIBRARIES}" "${LDNS_LIBRARIES}" )
include_directories( ./lib usr/local/include usr/include "${UNBOUND_INCLUDE_DIR}" "${LDNS_INCLUDE_DIRS}" )


add_executable(SecureFetch ./secure-fetch.c)
target_link_libraries( SecureFetch ${PROJECT_LINK_LIBS} )
