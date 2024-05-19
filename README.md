# MY DEBUGGER
This is my attempt to create a debugger in cpp. <br>
Currently, one can set breakpoints and continue execution, read and write any register and also memory<BR>

## How to install?
1. Download this repositary.
2. Compile using command 
    ```
    g++ -I include ./include/cpp/* -o debugg
    ```
## How to use?
- To run 
    ```
    ./debugg <your_program>
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
- To exit
    ```
    q
- To execute shell command
    ```
    cmd <command>
- For help
    ```
    help