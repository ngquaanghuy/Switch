# Download doctest if not present
if(NOT EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/doctest.h)
    file(DOWNLOAD
        https://raw.githubusercontent.com/doctest/doctest/v2.4.11/doctest/doctest.h
        ${CMAKE_CURRENT_SOURCE_DIR}/doctest.h
        TIMEOUT 30
        STATUS DOWNLOAD_STATUS
    )
    list(GET DOWNLOAD_STATUS 0 STATUS_CODE)
    if(NOT STATUS_CODE EQUAL 0)
        message(FATAL_ERROR "Failed to download doctest.h")
    endif()
endif()

# ---------------------------------------------------------------------------
# test_encode (encoding: base16/32/58/62/64)
# ---------------------------------------------------------------------------
add_executable(test_encode
    test_encode.cpp
    ${CMAKE_SOURCE_DIR}/src/encode.cpp
)

target_include_directories(test_encode PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_compile_features(test_encode PRIVATE cxx_std_17)

add_test(NAME test_encode COMMAND test_encode)

# ---------------------------------------------------------------------------
# test_cli_encode (CLI parsing + encoding end-to-end)
# ---------------------------------------------------------------------------
add_executable(test_cli_encode
    test_cli_encode.cpp
    ${CMAKE_SOURCE_DIR}/src/cli.cpp
    ${CMAKE_SOURCE_DIR}/src/encode.cpp
    ${CMAKE_SOURCE_DIR}/src/encrypt.cpp
    ${CMAKE_SOURCE_DIR}/src/obfuscate.cpp
    ${CMAKE_SOURCE_DIR}/src/scramble.cpp
)

target_include_directories(test_cli_encode PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_compile_features(test_cli_encode PRIVATE cxx_std_17)
target_link_libraries(test_cli_encode PRIVATE OpenSSL::Crypto ${SODIUM})
target_include_directories(test_cli_encode PRIVATE ${SODIUM_INCLUDE_DIR})

add_test(NAME test_cli_encode COMMAND test_cli_encode)

# ---------------------------------------------------------------------------
# test_encrypt (AES encryption unit tests)
# ---------------------------------------------------------------------------
add_executable(test_encrypt
    test_encrypt.cpp
    ${CMAKE_SOURCE_DIR}/src/encrypt.cpp
)

target_include_directories(test_encrypt PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_compile_features(test_encrypt PRIVATE cxx_std_17)
target_link_libraries(test_encrypt PRIVATE OpenSSL::Crypto ${SODIUM})
target_include_directories(test_encrypt PRIVATE ${SODIUM_INCLUDE_DIR})

add_test(NAME test_encrypt COMMAND test_encrypt)

# ---------------------------------------------------------------------------
# test_cli_encrypt (CLI parsing + AES encryption end-to-end)
# ---------------------------------------------------------------------------
add_executable(test_cli_encrypt
    test_cli_encrypt.cpp
    ${CMAKE_SOURCE_DIR}/src/cli.cpp
    ${CMAKE_SOURCE_DIR}/src/encrypt.cpp
    ${CMAKE_SOURCE_DIR}/src/encode.cpp
    ${CMAKE_SOURCE_DIR}/src/obfuscate.cpp
    ${CMAKE_SOURCE_DIR}/src/scramble.cpp
)

target_include_directories(test_cli_encrypt PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_compile_features(test_cli_encrypt PRIVATE cxx_std_17)
target_link_libraries(test_cli_encrypt PRIVATE OpenSSL::Crypto ${SODIUM})
target_include_directories(test_cli_encrypt PRIVATE ${SODIUM_INCLUDE_DIR})

add_test(NAME test_cli_encrypt COMMAND test_cli_encrypt)

# ---------------------------------------------------------------------------
# test_scramble (scramble identifiers unit tests)
# ---------------------------------------------------------------------------
add_executable(test_scramble
    test_scramble.cpp
    ${CMAKE_SOURCE_DIR}/src/scramble.cpp
)

target_include_directories(test_scramble PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_compile_features(test_scramble PRIVATE cxx_std_17)

add_test(NAME test_scramble COMMAND test_scramble)

# ---------------------------------------------------------------------------
# test_obf (obfuscation pipeline stacking end-to-end tests)
# ---------------------------------------------------------------------------
add_executable(test_obf
    test_obf.cpp
    ${CMAKE_SOURCE_DIR}/src/obfuscate.cpp
    ${CMAKE_SOURCE_DIR}/src/scramble.cpp
)

target_include_directories(test_obf PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_compile_features(test_obf PRIVATE cxx_std_17)

add_test(NAME test_obf COMMAND test_obf WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})