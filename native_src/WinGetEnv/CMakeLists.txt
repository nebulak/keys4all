cmake_minimum_required(VERSION 2.8.9)
project (WinGetEnv)

link_directories( ./lib/build usr/local/lib)
include_directories( ./lib usr/local/include)


add_executable(WinGetEnv main.c)
