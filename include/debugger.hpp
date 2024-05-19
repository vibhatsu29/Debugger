#ifndef MYDBG_DEBUGGER_HPP
#define MYDBG_DEBUGGER_HPP
#include <utility>
#include <string>
#include <linux/types.h>
#include <unordered_map>
#include "breakpoint.hpp"
namespace mydbg
{
    class debugger
    {
    public:
        debugger(std::string prog_name, pid_t pid, uint64_t addr) : m_prog_name{std::move(prog_name)}, m_pid{pid}, m_base_addr{addr} {}
        void run();
        void handle_command(const std::string &line);
        void continue_execution();
        void set_breakpoint_at(uint64_t addr);
        void dump_registers();
        uint64_t read_memory(uint64_t addr);
        void write_memory(uint64_t addr, uint64_t value);
        uint64_t get_pc();
        void set_pc(uint64_t pc);
        void step_over_breakpoint();
        void wait_for_signal();

    private:
        std::string m_prog_name;
        pid_t m_pid;
        std::unordered_map<std::intptr_t, breakpoint> m_breakpoints;
        uint64_t m_base_addr;
    };
}
#endif