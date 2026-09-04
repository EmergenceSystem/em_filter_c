cmake_minimum_required(VERSION 3.16)
project(em_filter C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED libsodium)

add_library(em_filter STATIC
    src/em_filter.c
    src/config.c
    src/crypto.c
    src/websocket.c
    src/connection.c
    src/html.c
    third_party/cJSON.c
)

target_include_directories(em_filter PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/third_party>
    $<BUILD_INTERFACE:${SODIUM_INCLUDE_DIRS}>
)

target_link_libraries(em_filter PUBLIC
    OpenSSL::SSL
    OpenSSL::Crypto
    Threads::Threads
    ${SODIUM_LIBRARIES}
)
target_link_directories(em_filter PUBLIC ${SODIUM_LIBRARY_DIRS})

# Echo filter example
add_executable(echo_filter examples/echo_filter.c)
target_link_libraries(echo_filter PRIVATE em_filter)

# ── Tests ────────────────────────────────────────────────────────────────
enable_testing()

add_executable(test_crypto tests/test_crypto.c)
target_link_libraries(test_crypto PRIVATE em_filter)
target_compile_definitions(test_crypto PRIVATE
    FIXTURE_PATH="${CMAKE_CURRENT_SOURCE_DIR}/fixtures/crypto_vectors.json")
add_test(NAME test_crypto COMMAND test_crypto)
