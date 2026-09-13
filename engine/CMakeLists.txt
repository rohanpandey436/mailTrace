cmake_minimum_required(VERSION 3.18)
project(mailtrace_engine LANGUAGES CXX VERSION 1.0.0)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

option(MAILTRACE_FETCH_PYBIND11 "Download pybind11 with FetchContent if it is not installed" OFF)

find_package(Python3 COMPONENTS Interpreter Development.Module REQUIRED)

find_package(pybind11 CONFIG QUIET)
if(NOT pybind11_FOUND)
  if(MAILTRACE_FETCH_PYBIND11)
    include(FetchContent)
    FetchContent_Declare(
      pybind11
      GIT_REPOSITORY https://github.com/pybind/pybind11.git
      GIT_TAG v2.13.6
    )
    FetchContent_MakeAvailable(pybind11)
  else()
    message(FATAL_ERROR
      "pybind11 not found.  Either:\n"
      "  pip install pybind11 && cmake -Dpybind11_DIR=$(python -m pybind11 --cmakedir) ...\n"
      "or configure with -DMAILTRACE_FETCH_PYBIND11=ON.")
  endif()
endif()

pybind11_add_module(mailtrace_engine
  src/sha256.cpp
  src/entropy.cpp
  src/parser.cpp
  src/bindings.cpp
)

target_include_directories(mailtrace_engine PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_compile_definitions(mailtrace_engine PRIVATE MAILTRACE_ENGINE_VERSION="${PROJECT_VERSION}")

if(MSVC)
  target_compile_options(mailtrace_engine PRIVATE /W4 /permissive- /EHsc)
else()
  target_compile_options(mailtrace_engine PRIVATE -Wall -Wextra -O2)
endif()
