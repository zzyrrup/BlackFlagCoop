cmake_minimum_required(VERSION 3.20)

# Portable CTest build for the peer-protocol codec.
# The root CMakeLists.txt refuses non-Windows targets because the ASI and
# Winsock transport are Windows-only. This file compiles only the codec.
project(BlackFlagCoopPeerProtocol LANGUAGES CXX)

set(BFC_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../..")

add_library(bfc_peer_protocol STATIC
    "${BFC_ROOT}/src/network/peer_protocol.cpp"
    "${BFC_ROOT}/src/network/peer_protocol.h"
)
target_include_directories(bfc_peer_protocol PUBLIC "${BFC_ROOT}/src")
target_compile_features(bfc_peer_protocol PUBLIC cxx_std_17)
if(MSVC)
    target_compile_options(bfc_peer_protocol PRIVATE /W4 /permissive- /EHsc)
else()
    target_compile_options(bfc_peer_protocol PRIVATE -Wall -Wextra -Werror -Wpedantic)
endif()

add_executable(BlackFlagCoopPeerProtocolTest main.cpp)
target_link_libraries(BlackFlagCoopPeerProtocolTest PRIVATE bfc_peer_protocol)
target_compile_features(BlackFlagCoopPeerProtocolTest PRIVATE cxx_std_17)
if(MSVC)
    target_compile_options(BlackFlagCoopPeerProtocolTest PRIVATE /W4 /permissive- /EHsc)
else()
    target_compile_options(BlackFlagCoopPeerProtocolTest PRIVATE -Wall -Wextra -Werror -Wpedantic)
endif()

enable_testing()
add_test(NAME PeerProtocolCodec COMMAND BlackFlagCoopPeerProtocolTest)
