cmake_minimum_required(VERSION 3.20)

# Standalone offline test. The root BlackFlagCoop target is Windows-only
# and is intentionally not pulled in here. This binary does not link the
# game, the ASI, or the session protocol.
project(BlackFlagCoopActionStateTest LANGUAGES CXX)

add_executable(ActionStateTest
    main.cpp
    ../../src/replication/action_state.cpp
)

target_include_directories(ActionStateTest PRIVATE ../../src)
target_compile_features(ActionStateTest PRIVATE cxx_std_17)

if(MSVC)
    target_compile_options(ActionStateTest PRIVATE /W4 /permissive- /EHsc)
else()
    target_compile_options(ActionStateTest PRIVATE -Wall -Wextra -Wpedantic)
endif()

enable_testing()
add_test(NAME ActionState COMMAND ActionStateTest)
