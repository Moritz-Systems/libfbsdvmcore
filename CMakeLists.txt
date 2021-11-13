cmake_minimum_required(VERSION 3.0)
cmake_policy(VERSION 3.0)
project(
    fbsdvmcore
    VERSION 0.0.0
    LANGUAGES C)

option(BUILD_SHARED_LIBS "Build shared libraries" ON)

include_directories(
    src
    /usr/src/sys)

add_library(
    fbsdvmcore
    src/fvc.c
    src/fvc_amd64.c
    src/fvc_arm.c
    src/fvc_i386.c
    src/fvc_minidump_aarch64.c
    src/fvc_minidump_amd64.c
    src/fvc_minidump_arm.c
    src/fvc_minidump_i386.c
    src/fvc_minidump_mips.c
    src/fvc_minidump_powerpc64.c
    src/fvc_minidump_powerpc64_hpt.c
    src/fvc_minidump_riscv.c
    src/fvc_powerpc.c
    src/fvc_powerpc64.c
    src/fvc_private.c
    src/fvc.h
    )
set_target_properties(
    fbsdvmcore
    PROPERTIES
    LINK_FLAGS "-Wl,-z,defs"
    LINK_LIBRARIES elf
    PUBLIC_HEADER "fvc.h"
    VERSION "${PROJECT_VERSION}"
    SOVERSION "${PROJECT_VERSION_MAJOR}")

set(ENABLE_TESTS ON)
find_program(KYUA kyua)
if(NOT KYUA)
  message(WARNING "kyua not found, tests will be disabled")
  set(ENABLE_TESTS OFF)
endif()

include(FindPkgConfig)
pkg_check_modules(ATF atf-c)
if(NOT ATF_FOUND)
  message(WARNING "atf-c not found, tests will be disabled")
  set(ENABLE_TESTS OFF)
else()
  string(REPLACE ";" " " ATF_CFLAGS "${ATF_CFLAGS}")
  string(REPLACE ";" " " ATF_LDFLAGS "${ATF_LDFLAGS}")
endif()

if(ENABLE_TESTS)
  add_subdirectory(tests)
endif()

include(GNUInstallDirs)
install(
    TARGETS fbsdvmcore
    DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    PUBLIC_HEADER DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}")

install(
    FILES
    man/fvc.3
    man/fvc_close.3
    man/fvc_geterr.3
    man/fvc_kerndisp.3
    man/fvc_native.3
    man/fvc_open.3
    man/fvc_read.3
    man/fvc_write.3
    DESTINATION "${CMAKE_INSTALL_MANDIR}/man3")
