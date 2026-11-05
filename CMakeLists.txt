cmake_minimum_required(VERSION 3.20)
project(libgphsm C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Compiler warnings
if(MSVC)
    add_compile_options(/W4 /WX-)
else()
    add_compile_options(-Wall -Wextra -Wno-unused-parameter -fPIC)
endif()

# Threading support
find_package(Threads REQUIRED)

# Include directories
include_directories(
    include
    include/pkcs11
    src
)

# Transport source
if(WIN32)
    set(TRANSPORT_SOURCES src/transport/serial_win32.c)
else()
    set(TRANSPORT_SOURCES src/transport/serial_posix.c)
endif()

# PKCS#11 shared library
add_library(libgphsm SHARED
    src/p11_general.c
    src/p11_slot.c
    src/p11_session.c
    src/p11_object.c
    src/p11_crypto.c
    src/transport/at_client.c
    ${TRANSPORT_SOURCES}
)

target_link_libraries(libgphsm PRIVATE Threads::Threads)

set_target_properties(libgphsm PROPERTIES
    C_VISIBILITY_PRESET default
    VISIBILITY_INLINES_HIDDEN OFF
    OUTPUT_NAME "gphsm"
    PREFIX "lib"
)

# Test executable
enable_testing()

add_executable(test_p11_mock
    tests/test_p11_mock.c
)

target_link_libraries(test_p11_mock PRIVATE libgphsm Threads::Threads)
add_test(NAME test_p11_mock COMMAND test_p11_mock)

# Installation targets
include(GNUInstallDirs)
install(TARGETS libgphsm
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    FILES_MATCHING PATTERN "*.h"
)
