# Registers the C test suite. Each test is a standalone executable linking zcio.
function(add_zcio_test NAME SRC)
    add_executable(${NAME} ${SRC})
    target_link_libraries(${NAME} PRIVATE zcio)
    target_include_directories(${NAME} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/c)
    add_test(NAME ${NAME} COMMAND ${NAME})
endfunction()

add_zcio_test(test_serial          tests/c/test_serial.c)
add_zcio_test(test_serial_advanced tests/c/test_serial_advanced.c)
add_zcio_test(test_ring            tests/c/test_ring.c)
add_zcio_test(test_membuf          tests/c/test_membuf.c)
add_zcio_test(test_stream          tests/c/test_stream.c)
add_zcio_test(test_net             tests/c/test_net.c)
add_zcio_test(test_util            tests/c/test_util.c)
add_zcio_test(test_dns             tests/c/test_dns.c)
add_zcio_test(test_archive         tests/c/test_archive.c)
add_zcio_test(test_hardening       tests/c/test_hardening.c)

# Networking/loopback tests. These now use the portable tests/c/zthread.h shim
# (pthreads on POSIX, Win32 threads on Windows), so they build on all platforms.
find_package(Threads REQUIRED)
add_zcio_test(test_tls          tests/c/test_tls.c)
add_zcio_test(test_tls_more     tests/c/test_tls_more.c)
add_zcio_test(test_http         tests/c/test_http.c)
add_zcio_test(test_net_advanced tests/c/test_net_advanced.c)
add_zcio_test(test_mcast        tests/c/test_mcast.c)
# Link the system threads lib where the shim uses pthreads (no-op on Windows).
foreach(t test_tls test_http test_mcast)
    target_link_libraries(${t} PRIVATE Threads::Threads)
endforeach()

# ---------------------------------------------------------------------------
# Language-binding tests (C++ / Python / Node) run as part of the same suite.
# C++ only needs a C++ compiler; Python and Node load the shared lib, so they
# are registered only when ZCIO_BUILD_SHARED produced the zcio_shared target.
# ---------------------------------------------------------------------------
option(ZCIO_BUILD_BINDING_TESTS "Register C++/Python/Node binding tests in CTest" ON)

if(ZCIO_BUILD_BINDING_TESTS)
    # --- C++ header-only RAII wrapper ---
    enable_language(CXX)
    find_package(Threads REQUIRED)
    add_executable(binding_cpp ${CMAKE_CURRENT_SOURCE_DIR}/bindings/cpp/test_zcio.cpp)
    target_link_libraries(binding_cpp PRIVATE zcio Threads::Threads)
    target_include_directories(binding_cpp PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
    set_target_properties(binding_cpp PROPERTIES CXX_STANDARD 17 CXX_STANDARD_REQUIRED ON)
    add_test(NAME binding_cpp COMMAND binding_cpp)

    if(TARGET zcio_shared)
        # --- Python (ctypes) ---
        find_program(ZCIO_PYTHON3 NAMES python3 python)
        if(ZCIO_PYTHON3)
            add_test(NAME binding_python
                COMMAND ${ZCIO_PYTHON3} ${CMAKE_CURRENT_SOURCE_DIR}/bindings/python/test_zcio.py)
            set_tests_properties(binding_python PROPERTIES
                ENVIRONMENT "ZCIO_LIBRARY=$<TARGET_FILE:zcio_shared>")
            message(STATUS "zcio: registered Python binding test (requires python3)")
        else()
            message(STATUS "zcio: python3 not found -- skipping Python binding test")
        endif()

        # --- Node (N-API) ---
        find_program(ZCIO_NODE NAMES node)
        # On Windows the launcher is npx.cmd; the extensionless "npx" is a Unix
        # shell script that cannot be executed directly, so prefer the .cmd.
        find_program(ZCIO_NPX  NAMES npx.cmd npx)
        if(ZCIO_NODE AND ZCIO_NPX)
            add_test(NAME binding_node COMMAND ${CMAKE_COMMAND}
                -DNODE=${ZCIO_NODE} -DNPX=${ZCIO_NPX}
                -DNODE_DIR=${CMAKE_CURRENT_SOURCE_DIR}/bindings/node
                -DLIB_DIR=$<TARGET_FILE_DIR:zcio_shared>
                -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/run_node_test.cmake)
            # node-gyp rebuild can be slow on the first run; give it room.
            set_tests_properties(binding_node PROPERTIES TIMEOUT 300)
            message(STATUS "zcio: registered Node binding test (requires node and npx)")
        else()
            message(STATUS "zcio: node/npx not found -- skipping Node binding test")
        endif()
    else()
        message(STATUS "zcio: Python/Node binding tests need -DZCIO_BUILD_SHARED=ON (skipped)")
    endif()
endif()
