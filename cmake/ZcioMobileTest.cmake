# ZcioMobileTest.cmake — run CTest suites on mobile targets.
#
# Cross-compiled test binaries cannot execute on the build host, so CTest is
# pointed at a launcher via CMAKE_CROSSCOMPILING_EMULATOR:
#
#   - Android : cmake/adb_runner.sh.in    — adb push + adb shell (device or
#               emulator; exit codes propagate via shell protocol v2)
#   - iOS sim : cmake/simctl_runner.sh.in — xcrun simctl spawn into the booted
#               simulator (shares the host filesystem)
#
# Usage — from zcio itself or from any dependent that fetched zcio:
#
#   include(${zcio_SOURCE_DIR}/cmake/ZcioMobileTest.cmake)
#   zcio_enable_mobile_testing()   # BEFORE the add_executable/add_test calls
#   ...
#
# The call is a no-op unless the build is actually cross-compiling for Android
# or the iOS simulator (a physical-iOS build has no host-driven way to run,
# so it stays a compile-only target). After it runs, every subsequently
# created test target inherits the launcher, and plain `ctest` works.
#
# Tests that need extra runtime files on the Android device (fixture .so's,
# data files) list them in the test's ENVIRONMENT as ZCIO_PUSH_FILES, a
# colon-separated list of host paths; the launcher pushes each beside the
# executable before running it.
#
# Cache knobs:
#   ZCIO_ADB                — adb executable (auto-detected from ANDROID_SDK_ROOT/
#                             ANDROID_HOME/~/Library/Android/sdk or PATH)
#   ZCIO_ANDROID_DEVICE_DIR — on-device staging dir [/data/local/tmp/zcio-tests]
#   ZCIO_SIM_DEVICE         — simulator UDID for simctl spawn [booted]

function(zcio_enable_mobile_testing)
    if(ANDROID OR CMAKE_SYSTEM_NAME STREQUAL "Android")
        set(_zcio_adb_hints)
        foreach(_root "$ENV{ANDROID_SDK_ROOT}" "$ENV{ANDROID_HOME}" "$ENV{HOME}/Library/Android/sdk")
            if(_root)
                list(APPEND _zcio_adb_hints "${_root}/platform-tools")
            endif()
        endforeach()
        find_program(ZCIO_ADB adb HINTS ${_zcio_adb_hints})
        if(NOT ZCIO_ADB)
            message(WARNING "zcio: adb not found — Android tests are built but "
                            "not runnable via ctest (set -DZCIO_ADB=/path/to/adb)")
            return()
        endif()

        set(ZCIO_ANDROID_DEVICE_DIR "/data/local/tmp/zcio-tests"
            CACHE STRING "On-device staging directory for pushed test binaries")

        set(_zcio_runner "${CMAKE_BINARY_DIR}/zcio-adb-runner.sh")
        configure_file("${CMAKE_CURRENT_FUNCTION_LIST_DIR}/adb_runner.sh.in"
                       "${_zcio_runner}" @ONLY
                       FILE_PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE
                                        GROUP_READ GROUP_EXECUTE
                                        WORLD_READ WORLD_EXECUTE)
        set(CMAKE_CROSSCOMPILING_EMULATOR "${_zcio_runner}" PARENT_SCOPE)
        message(STATUS "zcio: mobile testing via adb (${ZCIO_ADB}) -> ${ZCIO_ANDROID_DEVICE_DIR}")

    elseif(CMAKE_SYSTEM_NAME STREQUAL "iOS" AND CMAKE_OSX_SYSROOT MATCHES "[Ss]imulator")
        set(ZCIO_SIM_DEVICE "booted"
            CACHE STRING "Simulator device (UDID or 'booted') for simctl spawn")

        set(_zcio_runner "${CMAKE_BINARY_DIR}/zcio-simctl-runner.sh")
        configure_file("${CMAKE_CURRENT_FUNCTION_LIST_DIR}/simctl_runner.sh.in"
                       "${_zcio_runner}" @ONLY
                       FILE_PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE
                                        GROUP_READ GROUP_EXECUTE
                                        WORLD_READ WORLD_EXECUTE)
        set(CMAKE_CROSSCOMPILING_EMULATOR "${_zcio_runner}" PARENT_SCOPE)
        message(STATUS "zcio: mobile testing via simctl spawn (device: ${ZCIO_SIM_DEVICE})")
    endif()
endfunction()
