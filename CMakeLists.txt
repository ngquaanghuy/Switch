cmake_minimum_required(VERSION 3.21)
project(Switch
    VERSION 0.1.0
    DESCRIPTION "Python code protection tool using C/C++"
    LANGUAGES CXX
)

# C++17 required for std::variant, std::string_view, if constexpr
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Ninja generator detection
if(NOT CMAKE_GENERATOR MATCHES "Ninja")
    message(WARNING "Ninja generator recommended for fastest builds. "
                    "Use: cmake -G Ninja -B build && cmake --build build")
endif()

# ---------------------------------------------------------------------------
# Cross-platform settings
# ---------------------------------------------------------------------------
if(WIN32)
    add_definitions(-DSWITCH_PLATFORM_WINDOWS)
    set(PLATFORM_LIBS ws2_32)
elseif(APPLE)
    add_definitions(-DSWITCH_PLATFORM_MACOS)
    set(PLATFORM_LIBS)
else()
    add_definitions(-DSWITCH_PLATFORM_LINUX)
    set(PLATFORM_LIBS dl pthread)
endif()

# ---------------------------------------------------------------------------
# OpenSSL (for AES encryption)
# ---------------------------------------------------------------------------
find_package(OpenSSL REQUIRED)
message(STATUS "Found OpenSSL ${OPENSSL_VERSION} at ${OPENSSL_INCLUDE_DIR}")

# ---------------------------------------------------------------------------
# libsodium (for ChaCha20/XChaCha20)
# ---------------------------------------------------------------------------
find_library(SODIUM sodium)
find_path(SODIUM_INCLUDE_DIR sodium.h)
if(NOT SODIUM OR NOT SODIUM_INCLUDE_DIR)
    message(FATAL_ERROR "libsodium not found. Install: sudo apt install libsodium-dev")
endif()
message(STATUS "Found libsodium: ${SODIUM}")

# ---------------------------------------------------------------------------
# Python 3.14 detection (prepare for future use)
# ---------------------------------------------------------------------------
find_package(Python3 3.14 EXACT QUIET)
if(Python3_FOUND)
    message(STATUS "Found Python ${Python3_VERSION} at ${Python3_EXECUTABLE}")
    add_definitions(-DSWITCH_HAS_PYTHON314)
    set(PYTHON_INCLUDE_DIRS ${Python3_INCLUDE_DIRS})
    set(PYTHON_LIBRARIES ${Python3_LIBRARIES})
else()
    message(STATUS "Python 3.14 not found — will build CLI-only (no runtime features)")
endif()

# ---------------------------------------------------------------------------
# Sources
# ---------------------------------------------------------------------------
set(SOURCES
    src/main.cpp
    src/cli.cpp
    src/encode.cpp
    src/encrypt.cpp
)

set(HEADERS
    include/switch/cli.hpp
    include/switch/encode.hpp
    include/switch/encrypt.hpp
    include/switch/version.hpp
)

add_executable(switch ${SOURCES} ${HEADERS})

target_include_directories(switch PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/include
)

target_link_libraries(switch PRIVATE ${PLATFORM_LIBS} OpenSSL::Crypto ${SODIUM})
target_include_directories(switch PRIVATE ${SODIUM_INCLUDE_DIR})

# Python linking (conditional, when protect/build features are added)
if(Python3_FOUND AND Python3_INCLUDE_DIRS)
    target_include_directories(switch PRIVATE ${PYTHON_INCLUDE_DIRS})
    # Link Python library when we start embedding/interfacing
    # target_link_libraries(switch PRIVATE ${PYTHON_LIBRARIES})
endif()

# ---------------------------------------------------------------------------
# Install
# ---------------------------------------------------------------------------
include(GNUInstallDirs)
install(TARGETS switch
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

# ---------------------------------------------------------------------------
# Testing
# ---------------------------------------------------------------------------
enable_testing()
add_subdirectory(tests)