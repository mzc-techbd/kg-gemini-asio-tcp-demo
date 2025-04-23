# server/CMakeLists.txt
cmake_minimum_required(VERSION 3.16)

# Define the server executable
add_executable(tcp_server
    main.cpp
    # Add other server source files here (e.g., session.cpp, server.cpp)
)

# Link against required libraries
# The targets Boost::system, Boost::coroutine, OpenSSL::SSL, OpenSSL::Crypto,
# and nlohmann_json::nlohmann_json should be available from the parent scope.
# Find required packages
find_package(CURL REQUIRED)
# find_package(nlohmann_json 3.2.0 REQUIRED) # Assuming nlohmann_json is found by parent

# Link against required libraries (excluding Asio target, using include dir instead)
# List libraries to link
set(server_libs
    OpenSSL::SSL
    OpenSSL::Crypto
    spdlog::spdlog
    CURL::libcurl # Add libcurl
    common        # Link against the common library
)

# Conditionally add nlohmann_json if the target exists
if(TARGET nlohmann_json::nlohmann_json)
    list(APPEND server_libs nlohmann_json::nlohmann_json)
endif()

target_link_libraries(tcp_server PRIVATE ${server_libs})

# Include directories
# Add Asio include path directly since we're not linking the target
# The headers are in the 'asio/include' subdirectory of the source dir
target_include_directories(tcp_server PRIVATE
    ${asio_SOURCE_DIR}/asio/include      # Asio headers
    ${nlohmann_json_SOURCE_DIR}/include # nlohmann_json headers
    ${CMAKE_CURRENT_SOURCE_DIR}/..        # Project root, allows finding "common/constants.h"
    ${spdlog_SOURCE_DIR}/include        # spdlog headers (needed by common/logger.h)
)

# Compile Definitions
# Define ASIO_STANDALONE to use Asio without Boost dependency
target_compile_definitions(tcp_server PRIVATE ASIO_STANDALONE)
# Add other specific include directories for the server if needed:
# target_include_directories(tcp_server PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)

# Set C++ standard for the target (optional, inherits from parent if not set)
# set_target_properties(tcp_server PROPERTIES CXX_STANDARD 17)