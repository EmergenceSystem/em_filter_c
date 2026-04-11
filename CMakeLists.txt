cmake_minimum_required(VERSION 3.16)
project(em_filter C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

add_library(em_filter STATIC
    src/em_filter.c
    src/config.c
    src/websocket.c
    src/connection.c
    src/html.c
    third_party/cJSON.c
)

target_include_directories(em_filter PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/third_party>
)

target_link_libraries(em_filter PUBLIC
    OpenSSL::SSL
    OpenSSL::Crypto
    Threads::Threads
)

# Echo filter example
add_executable(echo_filter examples/echo_filter.c)
target_link_libraries(echo_filter PRIVATE em_filter)
