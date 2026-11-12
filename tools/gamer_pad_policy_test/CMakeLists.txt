cmake_minimum_required(VERSION 3.20)

# Standalone on purpose: the root project refuses non-Windows hosts because the
# ASI targets the game. This target is engine-free and can configure anywhere.
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    project(BlackFlagCoopGamerPadPolicy LANGUAGES CXX)
endif()

set(BFC_GAMER_PAD_POLICY_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../src/coop")

add_library(bfc_gamer_pad_policy STATIC
    "${BFC_GAMER_PAD_POLICY_DIR}/gamer_pad_policy.cpp"
    "${BFC_GAMER_PAD_POLICY_DIR}/gamer_pad_policy.h"
)

target_include_directories(bfc_gamer_pad_policy PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/../../src"
)

target_compile_features(bfc_gamer_pad_policy PUBLIC cxx_std_17)

if(MSVC)
    target_compile_options(bfc_gamer_pad_policy PRIVATE /W4 /permissive- /EHsc)
else()
    target_compile_options(bfc_gamer_pad_policy PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_executable(bfc_gamer_pad_policy_test
    "${CMAKE_CURRENT_SOURCE_DIR}/main.cpp"
)

target_link_libraries(bfc_gamer_pad_policy_test PRIVATE bfc_gamer_pad_policy)

if(MSVC)
    target_compile_options(bfc_gamer_pad_policy_test PRIVATE /W4 /permissive- /EHsc)
else()
    target_compile_options(bfc_gamer_pad_policy_test PRIVATE -Wall -Wextra -Wpedantic)
endif()

set_target_properties(bfc_gamer_pad_policy_test PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    enable_testing()
endif()

add_test(NAME GamerPadPolicy COMMAND bfc_gamer_pad_policy_test)
