cmake_minimum_required(VERSION 3.20)

option(BITCASK_BUILD_TESTS "Build tests" OFF)

project(bitcask-cpp LANGUAGES CXX)

find_package(Threads REQUIRED)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Determine whether this is a standalone project or
# included by other projects.
if(CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
  set(CMAKE_CXX_STANDARD 20)
  set(CMAKE_CXX_STANDARD_REQUIRED ON)
  set(CMAKE_CXX_EXTENSIONS OFF)

  set(BITCASK_BUILD_TESTS ON)
elseif(NOT CMAKE_CXX_STANDARD)
  set(CMAKE_CXX_STANDARD 20)
  set(CMAKE_CXX_STANDARD_REQUIRED ON)
endif()

if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -stdlib=libc++")
  set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -stdlib=libc++ -lc++abi")
endif()

set(BITCASK_PUBLIC_INCLUDE_DIR "include/bitcask")

add_library(bitcask INTERFACE)

target_include_directories(bitcask
  INTERFACE
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

# Tests.
if(BITCASK_BUILD_TESTS)
  enable_testing()
  add_subdirectory(test)

  # Local test projects.
  if(IS_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/junk")
    add_subdirectory(junk EXCLUDE_FROM_ALL)
  endif()
endif()
