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

add_executable(test_cli_encode
    test_cli_encode.cpp
    ${CMAKE_SOURCE_DIR}/src/cli.cpp
    ${CMAKE_SOURCE_DIR}/src/encode.cpp
)

target_include_directories(test_cli_encode PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_compile_features(test_cli_encode PRIVATE cxx_std_17)

add_test(NAME test_cli_encode COMMAND test_cli_encode)