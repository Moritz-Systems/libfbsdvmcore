cmake_minimum_required(VERSION 3.0)
cmake_policy(VERSION 3.0)
project(
    fbsdvmcore
    VERSION 0.0.0
    LANGUAGES C)

option(BUILD_SHARED_LIBS "Build shared libraries" ON)

include_directories(
    ${CMAKE_BINARY_DIR}/lib
    lib)

include(CheckIncludeFile)
check_include_file("sys/endian.h" HAVE_SYS_ENDIAN_H)
if(NOT HAVE_SYS_ENDIAN_H)
  check_include_file("endian.h" HAVE_ENDIAN_H)
  if(NOT HAVE_ENDIAN_H)
    message(FATAL_ERROR "Unable to find a working [sys/]endian.h")
  endif()
endif()

configure_file(lib/config.h.in lib/config.h)

add_library(
    fbsdvmcore
    lib/fvc.c
    lib/fvc_amd64.c
    lib/fvc_arm.c
    lib/fvc_i386.c
    lib/fvc_minidump_aarch64.c
    lib/fvc_minidump_amd64.c
    lib/fvc_minidump_arm.c
    lib/fvc_minidump_i386.c
    lib/fvc_minidump_mips.c
    lib/fvc_minidump_powerpc64.c
    lib/fvc_minidump_powerpc64_hpt.c
    lib/fvc_minidump_riscv.c
    lib/fvc_powerpc.c
    lib/fvc_powerpc64.c
    lib/fvc_private.c
    lib/fvc.h
    )
set_target_properties(
    fbsdvmcore
    PROPERTIES
    LINK_FLAGS "-Wl,-z,defs"
    LINK_LIBRARIES elf
    PUBLIC_HEADER "fvc.h"
    VERSION "${PROJECT_VERSION}"
    SOVERSION "${PROJECT_VERSION_MAJOR}")

add_executable(
    minidump-to-elf
    src/minidump-to-elf.c)
target_link_libraries(
    minidump-to-elf
    fbsdvmcore
    elf)

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
    man/fvc_open.3
    man/fvc_read.3
    DESTINATION "${CMAKE_INSTALL_MANDIR}/man3")
