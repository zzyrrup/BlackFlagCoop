cmake_minimum_required(VERSION 3.20)

project(BlackFlagCoop
    VERSION 0.8.0
    LANGUAGES CXX
)

# BlackFlag Resynced is a 64-bit Windows game. Refuse other architectures early.
if(NOT WIN32)
    message(FATAL_ERROR "BlackFlagCoop only supports Windows.")
endif()

if(CMAKE_SIZEOF_VOID_P EQUAL 4)
    message(FATAL_ERROR "BlackFlagCoop must be built as a 64-bit (x64) binary.")
endif()

# Shared networking + logging used by the ASI and the localhost net test.
add_library(BlackFlagCoopNet STATIC
    src/logger.cpp
    src/logger.h
    src/network/network.cpp
    src/network/network.h
    src/network/session.cpp
    src/network/session.h
    src/network/protocol.h
    src/network/player_state.cpp
    src/network/player_state.h
    src/game/runtime_diag.cpp
    src/game/runtime_diag.h
    src/game/player_telemetry.cpp
    src/game/player_telemetry.h
    src/game/player_probe.cpp
    src/game/player_probe.h
    src/game/spawn_contract.cpp
    src/game/spawn_contract.h
    src/game/puppet_lifecycle.cpp
    src/game/puppet_lifecycle.h
    src/game/builder_path.cpp
    src/game/builder_path.h
    src/game/player_retention.cpp
    src/game/player_retention.h
)

target_include_directories(BlackFlagCoopNet PUBLIC src)
target_compile_features(BlackFlagCoopNet PUBLIC cxx_std_17)
target_compile_definitions(BlackFlagCoopNet PUBLIC
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    UNICODE
    _UNICODE
)
target_link_libraries(BlackFlagCoopNet PUBLIC ws2_32 Psapi)

if(MSVC)
    target_compile_options(BlackFlagCoopNet PRIVATE
        /W4
        /permissive-
        /EHsc
    )
endif()

add_library(BlackFlagCoop SHARED
    src/main.cpp
    src/splash.cpp
    src/splash.h
)

target_link_libraries(BlackFlagCoop PRIVATE
    BlackFlagCoopNet
    gdiplus
)

target_compile_features(BlackFlagCoop PRIVATE cxx_std_17)

set_target_properties(BlackFlagCoop PROPERTIES
    OUTPUT_NAME "BlackFlagCoop"
    PREFIX ""
    SUFFIX ".asi"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
)

if(MSVC)
    target_compile_options(BlackFlagCoop PRIVATE
        /W4
        /permissive-
        /EHsc
    )
endif()

add_custom_command(TARGET BlackFlagCoop POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${CMAKE_SOURCE_DIR}/BlackFlagCoop_splash.png"
        "$<TARGET_FILE_DIR:BlackFlagCoop>/BlackFlagCoop_splash.png"
    COMMENT "Copying BlackFlagCoop startup artwork beside the ASI"
)

# Separate console app for networking tests (never injected into the game).
add_executable(BlackFlagCoopNetTest
    tools/net_test/main.cpp
)

target_link_libraries(BlackFlagCoopNetTest PRIVATE BlackFlagCoopNet)

set_target_properties(BlackFlagCoopNetTest PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

if(MSVC)
    target_compile_options(BlackFlagCoopNetTest PRIVATE
        /W4
        /permissive-
        /EHsc
    )
endif()

# Offline read-only string probe for on-disk executables (never injected).
add_executable(BlackFlagCoopExeStringProbe
    tools/exe_string_probe/main.cpp
)

target_compile_features(BlackFlagCoopExeStringProbe PRIVATE cxx_std_17)
target_compile_definitions(BlackFlagCoopExeStringProbe PRIVATE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    UNICODE
    _UNICODE
)

set_target_properties(BlackFlagCoopExeStringProbe PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

if(MSVC)
    target_compile_options(BlackFlagCoopExeStringProbe PRIVATE
        /W4
        /permissive-
        /EHsc
    )
endif()

add_executable(BlackFlagCoopSpawnContractTest
    tools/spawn_contract_test/main.cpp
)

target_link_libraries(BlackFlagCoopSpawnContractTest PRIVATE BlackFlagCoopNet)

set_target_properties(BlackFlagCoopSpawnContractTest PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

if(MSVC)
    target_compile_options(BlackFlagCoopSpawnContractTest PRIVATE
        /W4
        /permissive-
        /EHsc
    )
endif()

add_executable(BlackFlagCoopPuppetLifecycleTest
    tools/puppet_lifecycle_test/main.cpp
)

target_link_libraries(BlackFlagCoopPuppetLifecycleTest PRIVATE BlackFlagCoopNet)

set_target_properties(BlackFlagCoopPuppetLifecycleTest PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

if(MSVC)
    target_compile_options(BlackFlagCoopPuppetLifecycleTest PRIVATE
        /W4
        /permissive-
        /EHsc
    )
endif()

add_executable(BlackFlagCoopBuilderPathTest
    tools/builder_path_test/main.cpp
)

target_link_libraries(BlackFlagCoopBuilderPathTest PRIVATE BlackFlagCoopNet)

set_target_properties(BlackFlagCoopBuilderPathTest PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

if(MSVC)
    target_compile_options(BlackFlagCoopBuilderPathTest PRIVATE
        /W4
        /permissive-
        /EHsc
    )
endif()

enable_testing()
add_test(
    NAME SpawnContract
    COMMAND BlackFlagCoopSpawnContractTest
)
add_test(
    NAME PuppetLifecycle
    COMMAND BlackFlagCoopPuppetLifecycleTest
)
add_test(
    NAME BuilderPath
    COMMAND BlackFlagCoopBuilderPathTest
)

add_executable(BlackFlagCoopPlayerRetentionTest
    tools/player_retention_test/main.cpp
)

target_link_libraries(BlackFlagCoopPlayerRetentionTest PRIVATE BlackFlagCoopNet)

set_target_properties(BlackFlagCoopPlayerRetentionTest PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

if(MSVC)
    target_compile_options(BlackFlagCoopPlayerRetentionTest PRIVATE
        /W4
        /permissive-
        /EHsc
    )
endif()

add_test(
    NAME PlayerRetention
    COMMAND BlackFlagCoopPlayerRetentionTest
)
