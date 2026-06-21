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

# Tests that spin loopback servers in threads.
if(NOT WIN32)
    find_package(Threads REQUIRED)
    add_zcio_test(test_tls          tests/c/test_tls.c)
    add_zcio_test(test_tls_more     tests/c/test_tls_more.c)
    add_zcio_test(test_http         tests/c/test_http.c)
    add_zcio_test(test_net_advanced tests/c/test_net_advanced.c)
    add_zcio_test(test_mcast        tests/c/test_mcast.c)
    target_link_libraries(test_tls          PRIVATE Threads::Threads)
    target_link_libraries(test_http         PRIVATE Threads::Threads)
    target_link_libraries(test_net_advanced PRIVATE Threads::Threads)
endif()
