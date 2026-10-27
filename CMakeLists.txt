cmake_minimum_required(VERSION 3.16)
project(procrib CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release)
endif()

add_library(procrib_core src/proctree.cpp src/render.cpp)
target_include_directories(procrib_core PUBLIC src)

add_executable(procrib src/main.cpp src/collect.cpp)
target_link_libraries(procrib PRIVATE procrib_core wintrust crypt32)
if(MINGW)
  target_link_options(procrib PRIVATE -static)
endif()

enable_testing()
add_executable(test_tree tests/test_tree.cpp)
target_link_libraries(test_tree PRIVATE procrib_core)
add_test(NAME tree COMMAND test_tree)
