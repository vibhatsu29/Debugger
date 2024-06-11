cmake_minimum_required(VERSION 3.0)
project(MyDbg)

add_compile_options(-std=c++14)

include_directories(ext/libelfin ext/linenoise include)
add_executable(mydbg src/mydbg.cpp ext/linenoise/linenoise.c)

add_executable(hello samples/Hello.cpp)
set_target_properties(hello
                      PROPERTIES COMPILE_FLAGS "-g -O0")


add_executable(variable samples/var.cpp)
set_target_properties(variable
                      PROPERTIES COMPILE_FLAGS "-gdwarf-2 -O0")


add_custom_target(
   libelfin
   COMMAND make
   WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/ext/libelfin
)
target_link_libraries(mydbg
                      ${PROJECT_SOURCE_DIR}/ext/libelfin/dwarf/libdwarf++.so
                      ${PROJECT_SOURCE_DIR}/ext/libelfin/elf/libelf++.so)
add_dependencies(mydbg libelfin)