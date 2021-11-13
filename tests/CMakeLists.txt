include_directories(
  ${CMAKE_TOP_SOURCE_DIRECTORY}/src)

set(TESTS
    kvm_close_test
    kvm_geterr_test
    kvm_open2_test
    kvm_read_test
    )

set(KYUAFILE "syntax(2)\ntest_suite(\"${CMAKE_PROJECT_NAME}\")\n")

foreach(T ${TESTS})
  add_executable(
      ${T}
      EXCLUDE_FROM_ALL
      ${T}.c
      kvm_test_common.c)
  set_target_properties(
      ${T}
      PROPERTIES
      COMPILE_FLAGS "${ATF_CFLAGS}"
      LINK_FLAGS "${ATF_LDFLAGS}"
      LINK_LIBRARIES fbsdvmcore)
  set(KYUAFILE "${KYUAFILE}atf_test_program{name=\"${T}\", }\n")
endforeach()

file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/Kyuafile" "${KYUAFILE}")

add_custom_target(
    test
    COMMAND kyua test
    DEPENDS ${TESTS}
    WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}")
