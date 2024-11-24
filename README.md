# MY DEBUGGER
This is my attempt to create a debugger in cpp with the help of external dependencies: linenoise and libelfin. <br>
I have used capstone for disassembling the code.<BR>
## Dependencies
- linenoise
- libelfin
- capstone

Install the dependencies in the appropriate directories.
## How to install?
1. Download this repositary.
2. Type the following commands in your terminal:
    ```zsh
    cmake -S . -B build
    cmake --buid build
    cd build
    ```
## How to use?
- To run 
    ```
    ./mydbg <your_program>
    ```
- To add breakpoint
    ```
    b <offset_of_your_breakpoint>
    ```
- To continue execution
    ```
    c
    ```
- To see all registers
    ```
    regs dump
    ```
- To read a particular register
    ```
    regs r <reg_name>
    ```
- To write in a particular register
    ```
    regs w <reg_name> <data_to_be_written_in_hexadecimal_format>
- To read a certain address in memory
    ```
    mem r <addr_offset>
- To write to a certain address in memory
    ```
    mem w <addr_offset> <data_to_be_written_in_hexadecimal_format>
- To view call stack
    ```
    bt
- To disassemble a function
    ```
    disass <func_name>
- To exit
    ```
    q
- To execute shell command
    ```
    cmd <command>
- For help
    ```
    help