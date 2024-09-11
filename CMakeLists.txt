cmake_minimum_required(VERSION 3.10)

project(gpgfs VERSION 1.0 LANGUAGES CXX)
if(NOT DEFINED BUILD_VERSION)
  set(BUILD_VERSION ${PROJECT_VERSION})
endif()
message(STATUS "Building version ${BUILD_VERSION}")

find_package(PkgConfig REQUIRED)
pkg_check_modules(fuse3 REQUIRED fuse3 IMPORTED_TARGET)
pkg_check_modules(gpgme REQUIRED gpgme IMPORTED_TARGET)

add_library(Gpgmepp STATIC IMPORTED)
set_target_properties(Gpgmepp PROPERTIES
  INTERFACE_INCLUDE_DIRECTORIES "/usr/include/gpgme++;/usr/include"
  INTERFACE_LINK_LIBRARIES "pthread;/usr/lib/x86_64-linux-gnu/libgpgmepp.a;-L/usr/lib/x86_64-linux-gnu -lassuan"
  IMPORTED_LOCATION "/usr/lib/x86_64-linux-gnu/libgpgmepp.a"
)
target_link_libraries(Gpgmepp INTERFACE PkgConfig::gpgme)

add_executable(gpgfs gpgfs.cpp)
target_link_libraries(gpgfs PRIVATE PkgConfig::fuse3 Gpgmepp)

install(TARGETS gpgfs DESTINATION bin)

set(CPACK_PACKAGE_NAME ${PROJECT_NAME})
set(CPACK_PACKAGE_VERSION ${BUILD_VERSION})
set(CPACK_PACKAGE_VENDOR "JCM")
set(CPACK_PACKAGE_CONTACT "JCM <jcm@jcm.re>")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY ${PROJECT_DESCRIPTION})
set(CPACK_DEBIAN_PACKAGE_HOMEPAGE "https://git.jcm.re/jcm/gpgfs")
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)
include(CPack)