cmake_minimum_required(VERSION 3.22)

#
# This file is generated only once,
# and is not re-generated if converter is called multiple times.
#
# User is free to modify the file as much as necessary
#

# Setup compiler settings
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS ON)

# Define the build type
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Debug")
endif()

set(CMAKE_C_FLAGS_DEBUG "-O0 -g3")
set(CMAKE_CXX_FLAGS_DEBUG "-O0 -g3")

# Set the project name
set(CMAKE_PROJECT_NAME STM32L476RG_VS_Cpp_test1)

# Enable compile command to ease indexing with e.g. clangd
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Core project settings
project(${CMAKE_PROJECT_NAME})
message("Build type: " ${CMAKE_BUILD_TYPE})

# Enable CMake support for ASM and C languages
enable_language(C CXX ASM)

# Create an executable object type
add_executable(${CMAKE_PROJECT_NAME})

# Add STM32CubeMX generated sources
add_subdirectory(cmake/stm32cubemx)

# Add system include paths as compile flags (after add_executable and add_subdirectory)
if(DEFINED ENV{CUBE_BUNDLE_PATH})
    set(TOOLCHAIN_PATH "$ENV{CUBE_BUNDLE_PATH}/gnu-tools-for-stm32/13.3.1+st.9")
    
    # Add as compile options instead of include directories
    target_compile_options(${CMAKE_PROJECT_NAME} PRIVATE
        "-I${TOOLCHAIN_PATH}/arm-none-eabi/include"
        "-I${TOOLCHAIN_PATH}/lib/gcc/arm-none-eabi/13.3.1/include"
        "-I${TOOLCHAIN_PATH}/arm-none-eabi/include/c++/13.3.1"
        "-I${TOOLCHAIN_PATH}/arm-none-eabi/include/c++/13.3.1/arm-none-eabi"
    )
    message(STATUS "Added system includes as compile flags from: ${TOOLCHAIN_PATH}")
else()
    message(WARNING "CUBE_BUNDLE_PATH environment variable not set.")
endif()

# Link directories setup
target_link_directories(${CMAKE_PROJECT_NAME} PRIVATE
    # Add user defined library search paths
)

# Add sources to executable
target_sources(${CMAKE_PROJECT_NAME} PRIVATE
    # Add user sources here
)

# Add include paths
target_include_directories(${CMAKE_PROJECT_NAME} PRIVATE
    # Add user defined include paths
)

# Add project symbols (macros)
target_compile_definitions(${CMAKE_PROJECT_NAME} PRIVATE
    # Add user defined symbols
)

# Remove wrong libob.a library dependency when using cpp files
list(REMOVE_ITEM CMAKE_C_IMPLICIT_LINK_LIBRARIES ob)

# Add linked libraries
target_link_libraries(${CMAKE_PROJECT_NAME}
    stm32cubemx

    # Add user defined libraries
)

# Add sources to executable
target_sources(${CMAKE_PROJECT_NAME} PRIVATE
    Modules/Logger_UART_Interface/Logger_UART_Interface.cpp
)

# Add include paths
target_include_directories(${PROJECT_NAME} PRIVATE
    Modules/Logger
    Modules/Logger_UART_Interface
)

# -------------------------------------------------------------------
# Log Hash Table Generation (add this block to your CMakeLists.txt)
# -------------------------------------------------------------------

find_package(Python3 REQUIRED COMPONENTS Interpreter)

set(LOG_HASH_SCRIPT ${CMAKE_SOURCE_DIR}/extract_log_hashes.py)
set(LOG_HASH_JSON   ${CMAKE_SOURCE_DIR}/log_hash_table.json)

set(LOG_SOURCE_DIRS
    ${CMAKE_SOURCE_DIR}/Core/src
    ${CMAKE_SOURCE_DIR}/Modules
    #${CMAKE_SOURCE_DIR}/Drivers
    # Add more directories here as your project grows
)

add_custom_command(
    OUTPUT ${LOG_HASH_JSON}
    COMMAND ${Python3_EXECUTABLE} ${LOG_HASH_SCRIPT} ${LOG_SOURCE_DIRS} ${LOG_HASH_JSON}
    DEPENDS ${LOG_HASH_SCRIPT}
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    COMMENT "Extracting log format strings and generating log_hash_table.json"
)

add_custom_target(generate_log_hash_table ALL DEPENDS ${LOG_HASH_JSON})

add_dependencies(${CMAKE_PROJECT_NAME} generate_log_hash_table)

# ------------------------------------------------------------------