cmake_minimum_required(VERSION 2.8)

set(CMAKE_CXX_STANDARD 11)

project(LeaksDetector)

set(VERSION_MAJOR "1")
set(VERSION_MINOR "0")
set(VERSION_PATCH "0")
set(VERSION ${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH})

file(GLOB SOURCES
    source/*.h
    source/*.cpp
)

add_definitions(-DMEMORY_MANAGEMENT)

add_executable(LeaksDetector ${SOURCES})
