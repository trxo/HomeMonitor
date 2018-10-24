cmake_minimum_required(VERSION 3.6)
project(websocket_server)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

set(SOURCE_FILES main.cpp frame.h epoll.h)
add_executable(websocket_server ${SOURCE_FILES})