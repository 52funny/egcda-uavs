cmake_minimum_required(VERSION 3.20)
project(pbc-rust)

find_library(pbc NAMES pbc libpbc HINTS /usr/local/lib)
add_executable(${PROJECT_NAME} wrapper.c)

target_link_libraries(${PROJECT_NAME} )
target_include_directories(${PROJECT_NAME} PUBLIC /usr/local/include)
