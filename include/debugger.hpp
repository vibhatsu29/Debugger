#ifndef MYDBG_DEBUGGER_HPP
#define MYDBG_DEBUGGER_HPP
#include <utility>
#include <string>
#include <linux/types.h>
#include <unordered_map>
#include <stdexcept>

#include "breakpoint.hpp"
#include "dwarf/dwarf++.hh"
#include "elf/elf++.hh"

namespace mydbg
{
    class debugger
    {
    public:
        debugger(std::string prog_name, pid_t pid) : m_prog_name{std::move(prog_name)}, m_pid{pid}
        {
            auto fd = open(m_prog_name.c_str(), O_RDONLY);
            m_elf = elf::elf{elf::create_mmap_loader(fd)};
            try
            {
                m_dwarf = dwarf::dwarf{dwarf::elf::create_loader(m_elf)};
            }
            catch (const std::exception &e)
            {
                is_dwarf_present = false;
                std::cout << "Failed to get the dwarf data." << std::endl;
            }
        }
        bool is_dwarf_present = true;
        void run();
        void handle_command(const std::string &line);
        void continue_execution();
        void set_breakpoint_at(uint64_t addr);
        void dump_registers();
        uint64_t read_memory(uint64_t addr);
        void write_memory(uint64_t addr, uint64_t value);
        auto get_pc() -> uint64_t;
        void set_pc(uint64_t pc);
        void step_over_breakpoint();
        void wait_for_signal();
        dwarf::die get_function_from_pc(uint64_t pc);
        dwarf::line_table::iterator get_line_entry_from_pc(uint64_t pc);
        void initialise_load_address();
        uint64_t offset_load_address(uint64_t addr);
        void print_source(const std::string &file_name, unsigned line, unsigned n_line_context = 2);
        siginfo_t get_signal_info();
        void handle_sigtrap(siginfo_t info);
        void print_backtrace();

    private:
        std::string m_prog_name;
        pid_t m_pid;
        std::unordered_map<std::intptr_t, breakpoint> m_breakpoints;
        uint64_t m_load_addr;
        elf::elf m_elf;
        dwarf::dwarf m_dwarf;
    };
}
#endif