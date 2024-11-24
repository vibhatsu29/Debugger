cmake_minimum_required(VERSION 3.11)
project(MYDbg)

find_package(Capstone)

if(NOT Capstone_FOUND)
    message(STATUS "Capstone not found, downloading and building Capstone...")

    include(FetchContent)
    FetchContent_Declare(
        capstone
        GIT_REPOSITORY https://github.com/aquynh/capstone.git
        GIT_TAG master
    )

    set(CAPSTONE_BUILD_STATIC ON)
    set(CAPSTONE_BUILD_SHARED OFF)
    set(CAPSTONE_INCLUDE_STATIC ON)
    set(OPTION_BUILD_TESTS OFF)

    FetchContent_MakeAvailable(capstone)

    set(CAPSTONE_INCLUDE_DIRS ${capstone_SOURCE_DIR}/include)
    set(CAPSTONE_LIBRARIES capstone)
else()
    set(CAPSTONE_INCLUDE_DIRS ${Capstone_INCLUDE_DIRS})
    set(CAPSTONE_LIBRARIES ${Capstone_LIBRARIES})
endif()
include_directories(ext/linenoise ext/libelfin include) 
add_executable(hello samples/hello.cpp)
set_target_properties(hello
                      PROPERTIES COMPILE_FLAGS "-g -O0")

add_executable(variable samples/variable.cpp)
set_target_properties(variable
                      PROPERTIES COMPILE_FLAGS "-gdwarf-2 -O0")

add_executable(unwinding samples/stack_unwinding.cpp)
set_target_properties(unwinding
                      PROPERTIES COMPILE_FLAGS "-g -O0")

add_executable(mydbg src/mydbg.cpp ext/linenoise/linenoise.c)

target_include_directories(mydbg PRIVATE
    ${CAPSTONE_INCLUDE_DIRS}
    ${PROJECT_SOURCE_DIR}/ext/libelfin
    ${PROJECT_SOURCE_DIR}/ext/linenoise
)

target_link_directories(mydbg PRIVATE ${capstone_BINARY_DIR})

add_custom_target(
   libelfin
   COMMAND make
   WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/ext/libelfin
)

target_link_libraries(mydbg PRIVATE ${CAPSTONE_LIBRARIES}
                     ${PROJECT_SOURCE_DIR}/ext/libelfin/dwarf/libdwarf++.so
                     ${PROJECT_SOURCE_DIR}/ext/libelfin/elf/libelf++.so)
add_dependencies(mydbg libelfin)