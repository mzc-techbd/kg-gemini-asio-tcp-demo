# CMakeLists.txt
cmake_minimum_required(VERSION 3.16)
project(AsioTcpDemo LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Include FetchContent module
include(FetchContent)

# --- Fetch Dependencies ---
# Using FetchContent to make the project self-contained.
# Note: Fetching/building Boost & OpenSSL can be time-consuming initially.

# Boost.System (Required by standalone Asio on some platforms)
# Assumes Boost is installed system-wide (e.g., brew install boost)
# find_package(Boost 1.70 REQUIRED COMPONENTS system) # Find system Boost, need at least 1.70 for good CMake support
# Provides target: Boost::system

# Standalone Asio (Much faster than full Boost fetch)
FetchContent_Declare(
  asio
  GIT_REPOSITORY https://github.com/chriskohlhoff/asio.git
  GIT_TAG        asio-1-34-2 # Using a specific stable tag
  GIT_SHALLOW    TRUE
  GIT_PROGRESS   TRUE
)
FetchContent_MakeAvailable(asio)
# Provides target: asio::asio (usually header-only, but FetchContent handles it)
# Ensure Asio headers are available (target_include_directories in subprojects is better)

# nlohmann/json (Header-only)
FetchContent_Declare(
  nlohmann_json
  GIT_REPOSITORY https://github.com/nlohmann/json.git
  GIT_TAG        v3.12.0 # Using specific stable tag
)
FetchContent_MakeAvailable(nlohmann_json)
# Provides target: nlohmann_json::nlohmann_json

# OpenSSL
# Requires build tools (Perl, make/ninja, C compiler).
FetchContent_Declare(
  openssl_fetch # Renamed to avoid conflict with potential find_package name
  GIT_REPOSITORY https://github.com/openssl/openssl.git
  GIT_TAG        openssl-3.4.1 # Using specific stable tag
  # OpenSSL's CMake support might require specific configurations or steps.
  # We rely on its build system being triggered correctly by MakeAvailable.
)
# Potential CMake options for OpenSSL build (if needed):
# set(OPENSSL_BUILD_TESTS OFF CACHE BOOL "Disable OpenSSL tests")
FetchContent_MakeAvailable(openssl_fetch)

# Explicitly find the package to define OpenSSL::SSL and OpenSSL::Crypto targets
find_package(OpenSSL REQUIRED)

# Expected targets: OpenSSL::SSL, OpenSSL::Crypto (provided by OpenSSL's CMake/build)
# Ensure headers are accessible (target_include_directories might handle this,
# but adding manually can be a fallback if needed)
# include_directories(${openssl_fetch_SOURCE_DIR}/include)

# spdlog (Header-only, but provides CMake target)
FetchContent_Declare(
  spdlog
  GIT_REPOSITORY https://github.com/gabime/spdlog.git
  GIT_TAG        v1.15.2 # Using specific stable tag
)
FetchContent_MakeAvailable(spdlog)
# Provides target: spdlog::spdlog


# --- Add Subdirectories ---
# These subdirectories contain their own CMakeLists.txt files
# defining the server and client targets. They will link against
# the targets provided by FetchContent above.

add_subdirectory(common) # Add the common library
add_subdirectory(server)
add_subdirectory(client)