cmake_minimum_required(VERSION 3.10)
project(common)

# spdlog is made available by FetchContent in the root CMakeLists.txt
# No need to find_package here.

add_library(common STATIC
    constants.h
    logger.h
    logger.cpp
)

target_include_directories(common PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${spdlog_SOURCE_DIR}/include # Add spdlog include directory
)

# Link spdlog to the common library
target_link_libraries(common PRIVATE spdlog::spdlog)