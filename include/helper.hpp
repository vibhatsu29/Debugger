#include <iostream>
#include <string>
#include <fcntl.h>
#include <cstdint>
namespace mydbg
{
    struct func_data
    {
        const uint8_t *func_code;
        size_t code_size;
        uint64_t address;
    };

}