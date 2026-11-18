cmake_minimum_required(VERSION 3.15)
project(snmk_fast_scanner LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(snmk_fast_scan
    src/fast_scanner.cpp
    src/fast_scanner.hpp
)

if(WIN32)
    target_link_libraries(snmk_fast_scan PRIVATE ws2_32)
else()
    target_link_libraries(snmk_fast_scan PRIVATE pthread)
endif()

# Output directly to bin directory
set_target_properties(snmk_fast_scan PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/bin"
)
