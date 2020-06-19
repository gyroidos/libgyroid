cmake_minimum_required(VERSION 3.7 FATAL_ERROR)
project(gyroidos VERSION 1.0 LANGUAGES C)

include(GNUInstallDirs)

set(CMAKE_BUILD_TYPE debug)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/../cmake)

set(CMAKE_VERBOSE_MAKEFILE ON)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Werror -Wno-unused-result -Wno-implicit-fallthrough -Werror=maybe-uninitialized -Wno-pointer-to-int-cast")

enable_testing()
add_subdirectory(libgyroid)
