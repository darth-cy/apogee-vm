# A C++ guest, built the way any C++ developer's would be: a CMake project and
# the SDK's toolchain file, no Rust anywhere in its build.
#
#     cmake -S guests/cpp-primes -B build \
#           -DCMAKE_TOOLCHAIN_FILE=<sdk>/cmake/apogee-rv64.cmake
#     cmake --build build
#
# docs/guest-program-manual.md §11 is the SDK; `test_support::guest_elf` builds
# this project against the SDK's pieces in this tree.
cmake_minimum_required(VERSION 3.20)
project(cpp-primes CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
add_executable(cpp-primes main.cpp)
