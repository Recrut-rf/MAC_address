cmake_minimum_required(VERSION 3.12)
project(MAC_address LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(SOURCES
    main.cpp
    MacPingDetector.cpp
)

set(HEADERS
    MacPingDetector.h
)

add_executable(${PROJECT_NAME} ${SOURCES} ${HEADERS})

target_link_libraries(${PROJECT_NAME} PRIVATE pthread)


