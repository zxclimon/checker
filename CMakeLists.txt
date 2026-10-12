cmake_minimum_required(VERSION 3.24)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
project(bedrock_checker VERSION 0.1.0 LANGUAGES C CXX)

if(NOT WIN32 OR NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR "Build with a Windows x64 toolchain")
endif()
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(FetchContent)
include(cmake/Yara.cmake)
FetchContent_Declare(json
    URL https://github.com/nlohmann/json/releases/download/v3.12.0/json.tar.xz
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
set(JSON_BuildTests OFF CACHE BOOL "" FORCE)
set(JSON_Install OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(json)

set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS rules/bedrock.yar)
file(READ rules/bedrock.yar BEDROCK_RULES)
configure_file(cmake/rules_embedded.h.in generated/rules_embedded.h @ONLY)

add_library(checker_core STATIC src/rules.cpp src/process.cpp src/files.cpp)
target_include_directories(checker_core PUBLIC src PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/generated")
target_compile_definitions(checker_core PUBLIC UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX _WIN32_WINNT=0x0A00)
target_link_libraries(checker_core PUBLIC yara PRIVATE psapi)

add_executable(checker src/main.cpp)
target_link_libraries(checker PRIVATE checker_core nlohmann_json::nlohmann_json)

function(configure_app target)
    if(MSVC)
        target_compile_options(${target} PRIVATE /W4 /WX /utf-8 /permissive-)
    else()
        target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic -Werror)
    endif()
endfunction()
configure_app(checker_core)
configure_app(checker)
if(MINGW)
    target_link_options(checker PRIVATE -static -municode)
endif()

configure_file("${yara_SOURCE_DIR}/COPYING" YARA-LICENSE.txt COPYONLY)
configure_file("${json_SOURCE_DIR}/LICENSE.MIT" JSON-LICENSE.txt COPYONLY)
install(TARGETS checker RUNTIME DESTINATION .)
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/YARA-LICENSE.txt"
    "${CMAKE_CURRENT_BINARY_DIR}/JSON-LICENSE.txt" DESTINATION .)

include(CTest)
if(BUILD_TESTING)
    add_executable(memory_fixture tests/memory_fixture.cpp)
    target_compile_definitions(memory_fixture PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)
    configure_app(memory_fixture)
    if(MINGW)
        target_link_options(memory_fixture PRIVATE -static -municode)
    endif()
    add_library(marker_fixture SHARED tests/marker_fixture.cpp)
    set_target_properties(marker_fixture PROPERTIES PREFIX "")
    configure_app(marker_fixture)
    if(MINGW)
        target_link_options(marker_fixture PRIVATE -static)
    endif()
    find_package(Python3 COMPONENTS Interpreter REQUIRED)
    add_test(NAME process_scan COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/check_process.py"
        --checker $<TARGET_FILE:checker> --fixture $<TARGET_FILE:memory_fixture>
        --dll $<TARGET_FILE:marker_fixture>)
    set_tests_properties(process_scan PROPERTIES TIMEOUT 120)
endif()
