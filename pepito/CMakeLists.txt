if ("${CMAKE_C_COMPILER_ID}" STREQUAL "GNU")
    set(warnings "-fno-stack-protector")
elseif ("${CMAKE_C_COMPILER_ID}" STREQUAL "Clang")
    set(warnings "-fno-address-sanitizer -fno-memsafety")
endif()

set(CMAKE_C_FLAGS   "${warnings}"
        CACHE STRING "Flags used by the compiler during all build types." FORCE)

project(pepito)
set(CMAKE_BUILD_TYPE Debug)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/includes)

set(CMAKE_SKIP_BUILD_RPATH true)

find_library(
        LIBSECRET NAMES secret
#        PATHS ${CMAKE_BINARY_DIR}/private/libsecret/ NO_DEFAULT_PATH
        PATHS ${CMAKE_CURRENT_SOURCE_DIR}/lib/ NO_DEFAULT_PATH
)

find_library(
        LIBSUPERSECRET NAMES supersecret
    #        PATHS ${CMAKE_BINARY_DIR}/private/libsecret/ NO_DEFAULT_PATH
        PATHS ${CMAKE_CURRENT_SOURCE_DIR}/lib/ NO_DEFAULT_PATH
)

add_executable(pepito src/daemon.c src/main.c src/network.c src/utils.c)

target_link_libraries(pepito ${LIBSECRET} ${LIBSUPERSECRET})

install(TARGETS pepito DESTINATION ${CMAKE_CURRENT_SOURCE_DIR}/)