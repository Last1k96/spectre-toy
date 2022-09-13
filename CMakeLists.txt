cmake_minimum_required(VERSION 3.23)
project(spectre-toy)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# strongly encouraged to enable this globally to avoid conflicts between
# -Wpedantic being enabled and -std=c++20 and -std=gnu++20 for example
# when compiling with PCH enabled
set(CMAKE_CXX_EXTENSIONS OFF)

# export compiler calls to a json file for clang-tidy & co
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# set default built type to Debug
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Debug)
endif()

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BUILD_TYPE}")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BUILD_TYPE}")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BUILD_TYPE}")

# HOWTO install libs
# include(GNUInstallDirs)
# install(TARGETS MyLib EXPORT MyLibTargets)

### Conan install

# Download automatically, you can also just copy the conan.cmake file
if(NOT EXISTS "${CMAKE_BINARY_DIR}/conan.cmake")
   message(STATUS "Downloading conan.cmake from https://github.com/conan-io/cmake-conan")
   file(DOWNLOAD "https://raw.githubusercontent.com/conan-io/cmake-conan/master/conan.cmake"
                  "${CMAKE_BINARY_DIR}/conan.cmake")
endif()

include(${CMAKE_BINARY_DIR}/conan.cmake)

conan_cmake_configure(CONANFILE conanfile.txt
BASIC_SETUP)
conan_cmake_autodetect(settings)
conan_cmake_install(PATH_OR_REFERENCE ..
                    BUILD missing
                    SETTINGS ${settings})

# conan_cmake_run(CONANFILE conanfile.txt
#                 BASIC_SETUP
#                 BUILD_TYPE ${CMAKE_BUILD_TYPE}
#                 BUILD missing)

# conan_cmake_run(REQUIRES
#                 catch2/2.13.9
#                 spdlog/1.10.0
#                 BASIC_SETUP
#                 BUILD missing
#                 GENERATORS cmake_find_package_multi CMakeDeps CMakeToolchain)

set(CMAKE_MODULE_PATH ${CMAKE_BINARY_DIR} ${CMAKE_MODULE_PATH})
set(CMAKE_PREFIX_PATH ${CMAKE_BINARY_DIR} ${CMAKE_PREFIX_PATH})

find_package(fmt REQUIRED)
find_package(spdlog REQUIRED)

add_executable(${PROJECT_NAME} main.cpp)
target_link_libraries(${PROJECT_NAME} PRIVATE fmt::fmt)


