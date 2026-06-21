# Registers the C test suite. Each test is a standalone executable linking zcio.
function(add_zcio_test NAME SRC)
    add_executable(${NAME} ${SRC})
    target_link_libraries(${NAME} PRIVATE zcio)
    target_include_directories(${NAME} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/c)
    add_test(NAME ${NAME} COMMAND ${NAME})
endfunction()

add_zcio_test(test_serial tests/c/test_serial.c)
add_zcio_test(test_ring   tests/c/test_ring.c)
add_zcio_test(test_membuf tests/c/test_membuf.c)
add_zcio_test(test_net    tests/c/test_net.c)
add_zcio_test(test_util   tests/c/test_util.c)
if(NOT WIN32)
    add_zcio_test(test_tls tests/c/test_tls.c)
    find_package(Threads REQUIRED)
    target_link_libraries(test_tls PRIVATE Threads::Threads)
endif()
