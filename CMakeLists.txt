cmake_minimum_required(VERSION 3.0)
cmake_policy(VERSION 3.0)
project(
    libfbsdvmcore
    VERSION 0.0.0
    LANGUAGES C)

option(BUILD_SHARED_LIBS "Build shared libraries" ON)

add_definitions(-DNO__SCCSID)
include_directories(
    /usr/src/lib/libkvm
    /usr/src/sys)

add_library(
    fbsdvmcore
    kvm.c
    kvm_amd64.c
    kvm_arm.c
    kvm_cptime.c
    kvm_getloadavg.c
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
    kvm_pcpu.c
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

include(GNUInstallDirs)
install(
    TARGETS fbsdvmcore
    DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    PUBLIC_HEADER DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}")

install(
    FILES
    kvm.3
    kvm_close.3
    kvm_counter_u64_fetch.3
    kvm_dpcpu_setcpu.3
    kvm_getargv.3
    kvm_getenvv.3
    kvm_geterr.3
    kvm_getloadavg.3
    kvm_getmaxcpu.3
    kvm_getpcpu.3
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
    kvm_read_zpcpu.3
    kvm_write.3
    DESTINATION "${CMAKE_INSTALL_MANDIR}/man3")
