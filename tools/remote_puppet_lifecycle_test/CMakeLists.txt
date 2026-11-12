cmake_minimum_required(VERSION 3.20)

# Standalone offline test. The root BlackFlagCoop lists are Windows-only and
# are also edited by other in-flight branches. This file builds the same
# sources with CTest on any host toolchain.
project(RemotePuppetLifecycleTest LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(remote_puppet_lifecycle_test
    ${CMAKE_CURRENT_LIST_DIR}/main.cpp
    ${CMAKE_CURRENT_LIST_DIR}/../../src/coop/remote_puppet_lifecycle.cpp
)
target_include_directories(remote_puppet_lifecycle_test PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/../../src
)
if(MSVC)
    target_compile_options(remote_puppet_lifecycle_test PRIVATE /W4 /permissive- /EHsc)
else()
    target_compile_options(remote_puppet_lifecycle_test PRIVATE -Wall -Wextra -Wpedantic)
endif()

enable_testing()
add_test(NAME remote_puppet_lifecycle COMMAND remote_puppet_lifecycle_test)
