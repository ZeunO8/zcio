# Driver for the Node binding test under CTest.
# Builds the N-API addon against the freshly-built shared lib, then runs the
# Node test suite. Invoked as:
#   cmake -DNODE=<node> -DNPX=<npx> -DNODE_DIR=<dir> -DLIB_DIR=<dir> -P run_node_test.cmake
#
# LIB_DIR is the directory holding libzcio.{so,dylib,dll}. It is exported so the
# addon links/loads against the build under test (not a stale ../../build copy).

set(ENV{ZCIO_LIB_DIR} "${LIB_DIR}")
set(ENV{DYLD_LIBRARY_PATH} "${LIB_DIR}:$ENV{DYLD_LIBRARY_PATH}")
set(ENV{LD_LIBRARY_PATH}   "${LIB_DIR}:$ENV{LD_LIBRARY_PATH}")

message(STATUS "node binding: building addon (ZCIO_LIB_DIR=${LIB_DIR})")
execute_process(
    COMMAND "${NPX}" --yes node-gyp rebuild
    WORKING_DIRECTORY "${NODE_DIR}"
    RESULT_VARIABLE build_rc
    OUTPUT_VARIABLE build_out
    ERROR_VARIABLE  build_err)
if(NOT build_rc EQUAL 0)
    message(FATAL_ERROR "node-gyp rebuild failed (${build_rc}):\n${build_out}\n${build_err}")
endif()

execute_process(
    COMMAND "${NODE}" test/test.js
    WORKING_DIRECTORY "${NODE_DIR}"
    RESULT_VARIABLE run_rc)
if(NOT run_rc EQUAL 0)
    message(FATAL_ERROR "node test suite failed (exit ${run_rc})")
endif()
