# 3.21+: first release that accepts CMAKE_C_STANDARD 23 and preset schema v3
# (toolchainFile / conditions), which the iOS/Android presets rely on.
cmake_minimum_required(VERSION 3.21)

project(zcio
    VERSION 1.0.9.0
    DESCRIPTION "Pure C23 streaming I/O library (C rewrite of iostreams)"
    LANGUAGES C)

# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------
# Mobile targets (the iOS family and Android) build dependency-free by
# default: neither OS ships OpenSSL as a public system library, so TLS
# defaults to the "none" backend there and archive support stays opt-in.
# Everything else zcio uses is core OS on both (libc, BSD sockets).
if(CMAKE_SYSTEM_NAME MATCHES "^(iOS|tvOS|watchOS|visionOS)$" OR ANDROID)
    set(ZCIO_MOBILE ON)
else()
    set(ZCIO_MOBILE OFF)
endif()

if(ZCIO_MOBILE)
    set(ZCIO_TLS_DEFAULT "none")
else()
    set(ZCIO_TLS_DEFAULT "openssl")
endif()
set(ZCIO_TLS "${ZCIO_TLS_DEFAULT}" CACHE STRING "TLS backend: openssl | none")
set_property(CACHE ZCIO_TLS PROPERTY STRINGS openssl none)
# Off by default: the archive backend FetchContent-clones a non-canonical
# libarchive fork. Opt in explicitly with -DZCIO_WITH_ARCHIVE=ON.
option(ZCIO_WITH_ARCHIVE "Build libarchive-backed archive support" OFF)
# Tests are host-run via ctest; when cross-compiling (iOS, Android, ...) the
# binaries cannot execute on the build machine, so default them off there.
if(CMAKE_CROSSCOMPILING)
    set(ZCIO_TESTS_DEFAULT OFF)
else()
    set(ZCIO_TESTS_DEFAULT ON)
endif()
option(ZCIO_BUILD_TESTS   "Build the C test suite"                  ${ZCIO_TESTS_DEFAULT})
option(ZCIO_BUILD_SHARED  "Build a shared library too"              OFF)
set(ZCIO_SANITIZE "" CACHE STRING "Sanitizers as a comma list, e.g. address,undefined,thread")

set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif()

# On MSVC-like front ends (incl. clang-cl) the UCRT marks standard functions
# such as fopen/strdup deprecated in favour of _s / underscore-prefixed names.
# Opt out globally so the portable library and tests stay warning-clean.
if(CMAKE_C_COMPILER_FRONTEND_VARIANT STREQUAL "MSVC")
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS _CRT_NONSTDC_NO_WARNINGS)
endif()

# Sanitizers apply globally (library + tests) so ctest exercises instrumented
# code. Compile and link must both carry the flag.
if(ZCIO_SANITIZE AND CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
    add_compile_options(-fsanitize=${ZCIO_SANITIZE} -fno-omit-frame-pointer)
    add_link_options(-fsanitize=${ZCIO_SANITIZE})
    message(STATUS "zcio sanitizers: ${ZCIO_SANITIZE}")
endif()

# ---------------------------------------------------------------------------
# TLS backend resolution
# ---------------------------------------------------------------------------
# Resolved before the source set and targets so a missing OpenSSL gracefully
# degrades to the no-TLS backend (warn + compile TLS out) instead of failing
# configuration outright. Demoting ZCIO_TLS here (a normal variable shadowing
# the cache) means every later "STREQUAL openssl" check picks the right path.
if(ZCIO_TLS STREQUAL "openssl")
    find_package(OpenSSL)
    if(OpenSSL_FOUND)
        message(STATUS "zcio TLS backend: OpenSSL")
    else()
        message(WARNING "zcio: OpenSSL not found — building WITHOUT TLS support. "
                        "Install an OpenSSL development package (or set OPENSSL_ROOT_DIR) "
                        "and reconfigure to enable it.")
        set(ZCIO_TLS "none")
    endif()
else()
    message(STATUS "zcio TLS backend: none (TLS compiled out)")
endif()

# ---------------------------------------------------------------------------
# Source set
# ---------------------------------------------------------------------------
set(ZCIO_SOURCES
    src/util.c
    src/socket_init.c
    src/stream.c
    src/serial.c
    src/ring.c
    src/membuf.c
    src/dns.c
    src/tcp.c
    src/udp.c
    src/mcast.c
    src/tls.c
    src/http.c
    src/http_util.c
    src/http_server.c
    src/h1.c
    src/h2.c
    src/hpack.c
    src/h3.c
    src/qpack.c
    src/ws.c
    src/archive.c)

# TLS backend selection: exactly one backend TU defines
# zcio_tls_install_default_backend().
if(ZCIO_TLS STREQUAL "openssl")
    list(APPEND ZCIO_SOURCES src/tls_openssl.c)
else()
    list(APPEND ZCIO_SOURCES src/tls_none.c)
endif()

# Build a static lib, plus optionally a shared one. All per-target settings are
# applied to every entry in ZCIO_LIBS so the two stay in lockstep.
add_library(zcio STATIC ${ZCIO_SOURCES})
add_library(zcio::zcio ALIAS zcio)
set(ZCIO_LIBS zcio)

if(ZCIO_BUILD_SHARED)
    add_library(zcio_shared SHARED ${ZCIO_SOURCES})
    set_target_properties(zcio_shared PROPERTIES
        OUTPUT_NAME zcio
        VERSION   ${PROJECT_VERSION}          # full lib version on the file
        SOVERSION ${PROJECT_VERSION_MAJOR})   # ABI version = MAJOR (SONAME)
    # Consumers of the shared lib must see ZCIO_SHARED so the header emits
    # dllimport on Windows; exported through the INSTALL/BUILD interface.
    target_compile_definitions(zcio_shared INTERFACE ZCIO_SHARED)
    list(APPEND ZCIO_LIBS zcio_shared)

    # On Windows the DLL's import library and the static library would both be
    # named zcio.lib and collide (ninja: "multiple rules generate zcio.lib").
    # Keep zcio.lib as the DLL import lib (the primary link target) and give the
    # static archive a distinct name, mirroring zlib's zlibstatic convention.
    if(WIN32)
        set_target_properties(zcio PROPERTIES OUTPUT_NAME zcio_static)
    endif()
endif()

if(ZCIO_WITH_ARCHIVE)
    include(FetchContent)
    set(ENABLE_TEST OFF CACHE BOOL "" FORCE)
    set(ENABLE_WERROR OFF CACHE BOOL "" FORCE)
    set(ENABLE_INSTALL OFF CACHE BOOL "" FORCE)
    message(STATUS "zcio: FetchContent libarchive")
    FetchContent_Declare(libarchive
        GIT_REPOSITORY https://github.com/ZeunO8/libarchive.git
        GIT_TAG master)
    FetchContent_MakeAvailable(libarchive)
    if(CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
        target_compile_options(archive_static PRIVATE
            -Wno-deprecated-declarations -Wno-incompatible-pointer-types-discards-qualifiers)
    endif()
    message(STATUS "zcio: archive support enabled (set -DZCIO_WITH_ARCHIVE=OFF to disable)")
else()
    message(STATUS "zcio: archive support disabled (set -DZCIO_WITH_ARCHIVE=ON to enable)")
endif()

foreach(lib IN LISTS ZCIO_LIBS)
    target_include_directories(${lib} PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>)
    # PIC unconditionally: the static archive is routinely linked into shared
    # binding/app libraries (Android .so, Python/Node modules, iOS frameworks).
    set_target_properties(${lib} PROPERTIES POSITION_INDEPENDENT_CODE ON)
    target_compile_definitions(${lib} PRIVATE ZCIO_BUILDING
        ZCIO_VERSION_STR="${PROJECT_VERSION}"
        ZCIO_VER_MAJOR=${PROJECT_VERSION_MAJOR}
        ZCIO_VER_MINOR=${PROJECT_VERSION_MINOR}
        ZCIO_VER_PATCH=${PROJECT_VERSION_PATCH}
        ZCIO_VER_TWEAK=${PROJECT_VERSION_TWEAK})
    if(CMAKE_C_COMPILER_FRONTEND_VARIANT STREQUAL "MSVC")
        # clang-cl / MSVC: GCC-style -Wall expands to -Weverything-class noise
        # here (pre-c23-compat, padded, unsafe-buffer-usage, ...). Use an MSVC
        # warning level instead. /W3 mirrors the intent of -Wall -Wextra without
        # the pedantic level-4 unused-parameter churn the vtable callbacks trip.
        target_compile_options(${lib} PRIVATE /W3)
    elseif(CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
        target_compile_options(${lib} PRIVATE -Wall -Wextra -Wno-unused-parameter)
    endif()
    if(ZCIO_TLS STREQUAL "openssl")
        target_link_libraries(${lib} PUBLIC OpenSSL::SSL OpenSSL::Crypto)
        target_compile_definitions(${lib} PRIVATE ZCIO_TLS_OPENSSL)
        if(CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
            target_compile_options(${lib} PRIVATE -Wno-deprecated-declarations)
        endif()
    endif()
    if(ZCIO_WITH_ARCHIVE)
        target_include_directories(${lib} PRIVATE ${libarchive_SOURCE_DIR}/libarchive)
        target_link_libraries(${lib} PRIVATE archive_static)
        target_compile_definitions(${lib} PRIVATE ZCIO_WITH_ARCHIVE)
    endif()
    if(WIN32)
        # bcrypt: BCryptGenRandom behind zcio_rand_bytes_ (WebSocket entropy).
        target_link_libraries(${lib} PUBLIC ws2_32 bcrypt)
    endif()
endforeach()
if(ZCIO_BUILD_SHARED)
    target_compile_definitions(zcio_shared PRIVATE ZCIO_BUILD_SHARED)
endif()

# ---------------------------------------------------------------------------
# pkg-config
# ---------------------------------------------------------------------------
include(GNUInstallDirs)
if(ZCIO_TLS STREQUAL "openssl")
    set(ZCIO_PC_REQUIRES_PRIVATE "openssl")
else()
    set(ZCIO_PC_REQUIRES_PRIVATE "")
endif()
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/cmake/zcio.pc.in
               ${CMAKE_CURRENT_BINARY_DIR}/zcio.pc @ONLY)

# ---------------------------------------------------------------------------
# Install + export (enables find_package(zcio) and pkg-config consumption)
# ---------------------------------------------------------------------------
include(CMakePackageConfigHelpers)

install(TARGETS ${ZCIO_LIBS}
        EXPORT zcioTargets
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/zcio
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(EXPORT zcioTargets
        NAMESPACE zcio::
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/zcio
        FILE zcioTargets.cmake)

configure_package_config_file(
        ${CMAKE_CURRENT_SOURCE_DIR}/cmake/zcioConfig.cmake.in
        ${CMAKE_CURRENT_BINARY_DIR}/zcioConfig.cmake
        INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/zcio)

write_basic_package_version_file(
        ${CMAKE_CURRENT_BINARY_DIR}/zcioConfigVersion.cmake
        VERSION ${PROJECT_VERSION}
        COMPATIBILITY SameMajorVersion)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/zcioConfig.cmake
              ${CMAKE_CURRENT_BINARY_DIR}/zcioConfigVersion.cmake
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/zcio)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/zcio.pc
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
if(ZCIO_BUILD_TESTS)
    enable_testing()
    include(${CMAKE_CURRENT_SOURCE_DIR}/tests/Tests.cmake)
endif()
