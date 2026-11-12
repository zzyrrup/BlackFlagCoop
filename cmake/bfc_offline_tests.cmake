# Offline CTest targets for modes that already exist on BlackFlagCoopNetTest.
# No game launch, no ASI copy, no install() rule.
# Included from the top-level CMakeLists.txt after that executable exists.

if(NOT TARGET BlackFlagCoopNetTest)
    message(FATAL_ERROR "bfc_offline_tests.cmake requires target BlackFlagCoopNetTest")
endif()

enable_testing()

add_test(
    NAME NetDiagSelfTest
    COMMAND BlackFlagCoopNetTest --diag-self-test
)
add_test(
    NAME NetSelfTest
    COMMAND BlackFlagCoopNetTest --self-test --port 27116
)

set_tests_properties(NetDiagSelfTest PROPERTIES
    TIMEOUT 30
    LABELS "offline;no-game;no-deploy"
)
set_tests_properties(NetSelfTest PROPERTIES
    TIMEOUT 60
    RESOURCE_LOCK "bfc_net_self_test_port"
    LABELS "offline;no-game;no-deploy"
)
