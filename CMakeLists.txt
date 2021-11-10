cmake_minimum_required(VERSION 3.0)
cmake_policy(VERSION 3.0)
project(
    fbsdvmcore
    VERSION 0.0.0
    LANGUAGES C)

option(BUILD_SHARED_LIBS "Build shared libraries" ON)

include_directories(
    .
    /usr/src/lib/libkvm
    /usr/src/sys)

add_library(
    fbsdvmcore
    kvm.c
    kvm_amd64.c
    kvm_arm.c
    kvm_getswapinfo.c
    kvm_i386.c
    kvm_minidump_aarch64.c
    kvm_minidump_amd64.c
    kvm_minidump_arm.c
    kvm_minidump_i386.c
    kvm_minidump_mips.c
    kvm_minidump_powerpc64.c
    kvm_minidump_powerpc64_hpt.c
    kvm_minidump_riscv.c
    kvm_powerpc.c
    kvm_powerpc64.c
    kvm_private.c
    kvm_proc.c
    kvm_vnet.c
    kvm.h
    )
set_target_properties(
    fbsdvmcore
    PROPERTIES
    LINK_FLAGS "-Wl,-z,defs"
    LINK_LIBRARIES elf
    PUBLIC_HEADER "kvm.h"
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
    kvm.3
    kvm_close.3
    kvm_geterr.3
    kvm_getprocs.3
    kvm_getswapinfo.3
    kvm_kerndisp.3
    kvm_native.3
    kvm_nlist.3
    kvm_nlist2.3
    kvm_open.3
    kvm_open2.3
    kvm_openfiles.3
    kvm_read.3
    kvm_read2.3
    kvm_write.3
    DESTINATION "${CMAKE_INSTALL_MANDIR}/man3")
