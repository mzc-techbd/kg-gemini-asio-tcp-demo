# client/CMakeLists.txt
cmake_minimum_required(VERSION 3.16)

# Define the client executable
add_executable(tcp_client
    main.cpp
    # Add other client source files here (e.g., client.cpp)
)

# Link against required libraries
# The targets Boost::system, Boost::coroutine, OpenSSL::SSL, OpenSSL::Crypto,
# and nlohmann_json::nlohmann_json should be available from the parent scope.
# Link against required libraries (excluding Asio target, using include dir instead)
# List libraries to link
set(client_libs
    OpenSSL::SSL
    OpenSSL::Crypto
    spdlog::spdlog
    common        # Link against the common library
)

# Conditionally add nlohmann_json if the target exists
if(TARGET nlohmann_json::nlohmann_json)
    list(APPEND client_libs nlohmann_json::nlohmann_json)
endif()

target_link_libraries(tcp_client PRIVATE ${client_libs})

# Include directories
# Add Asio include path directly since we're not linking the target
# The headers are in the 'asio/include' subdirectory of the source dir
target_include_directories(tcp_client PRIVATE
    ${asio_SOURCE_DIR}/asio/include      # Asio headers
    ${nlohmann_json_SOURCE_DIR}/include # nlohmann_json headers
    ${CMAKE_CURRENT_SOURCE_DIR}/..        # Project root, allows finding "common/constants.h"
    ${spdlog_SOURCE_DIR}/include        # spdlog headers (needed by common/logger.h)
)
# Add other specific include directories for the client if needed:
# target_include_directories(tcp_client PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)

# Compile Definitions
# Define ASIO_STANDALONE to use Asio without Boost dependency
target_compile_definitions(tcp_client PRIVATE ASIO_STANDALONE)

# Set C++ standard for the target (optional, inherits from parent if not set)
# set_target_properties(tcp_client PROPERTIES CXX_STANDARD 17)