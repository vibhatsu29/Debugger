#include <iostream>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/personality.h>
#include <vector>
#include <sstream>
#include <iomanip>

#include "linenoise.h"

#include "debugger.hpp"
#include "breakpoint.hpp"
#include "regs.hpp"

using namespace mydbg;

std::vector<std::string> split(const std::string &s, char delimiter)
{
    std::vector<std::string> out{};
    std::stringstream ss{s};
    std::string item;

    while (std::getline(ss, item, delimiter))
    {
        out.push_back(item);
    }

    return out;
}

bool is_prefix(const std::string &s, const std::string &of)
{
    if (s.size() > of.size())
        return false;
    return std::equal(s.begin(), s.end(), of.begin());
}

void debugger::run()
{
    int wait_status;
    auto options = 0;
    waitpid(m_pid, &wait_status, options);
    char *line = nullptr;
    while ((line = linenoise("\x1B[1m\x1B[92mmydbg> \x1B[0m")) != nullptr)
    {
        handle_command(line);
        linenoiseHistoryAdd(line);
        linenoiseHistoryFree();
    }
}
void debugger::handle_command(const std::string &line)
{
    auto args = split(line, ' ');
    auto command = args[0];
    if (is_prefix(command, "c"))
    {
        continue_execution();
    }
    else if (is_prefix(command, "b"))
    {
        std::string addr{args[1]};
        set_breakpoint_at(std::stol(addr, 0, 16));
    }
    else if (is_prefix(command, "regs"))
    {
        if (is_prefix(args[1], "dump"))
        {
            dump_registers();
        }
        else if (is_prefix(args[1], "r"))
        {
            if (args.size() != 3)
            {
                std::cerr << "\x1B[1m\x1B[91mInvalid number of arguments\x1B[38;5;28m\nPlease provide a register name in the format like rip,rax\x1B[0m\n";
                return;
            }
            std::cout << "\x1B[38;5;27m" << args[2] << "\x1B[0m:\t0x" << std::hex << get_register_value(m_pid, get_register_from_name(args[2])) << std::endl;
        }
        else if (is_prefix(args[1], "w"))
        {
            std::string val{args[3], 2};
            set_register_value(m_pid, get_register_from_name(args[2]), std::stol(val, 0, 16));
        }
        else
        {
            std::cerr << "\x1B[1m\x1B[91mUnknown command\x1B[0m\n";
        }
    }
    else if (is_prefix(command, "mem"))
    {
        std::string addr{args[2], 2};
        if (is_prefix(args[1], "r"))
        {
            std::cout << std::hex << read_memory(std::stol(addr, 0, 16)) << std::endl;
        }
        else if (is_prefix(args[1], "w"))
        {
            std::string val{args[3], 2};
            write_memory(std::stol(addr, 0, 16), std::stol(val, 0, 16));
        }
    }
    else if (is_prefix(command, "so"))
    {
        step_over_breakpoint();
    }
    else if (is_prefix(command, "q"))
    {
        kill(m_pid, SIGKILL);
        std::cout << "\x1B[1m\x1B[38;5;196mExiting debugger\x1B[0m\n";
        exit(0);
    }
    else if (is_prefix(command, "si"))
    {
        ptrace(PTRACE_SINGLESTEP, m_pid, nullptr, nullptr);
        wait_for_signal();
    }
    else
    {
        std::cerr << "\x1B[1m\x1B[91mUnknown command\x1B[0m\n";
    }
}
uint64_t debugger::read_memory(uint64_t address)
{
    return ptrace(PTRACE_PEEKDATA, m_pid, address, nullptr);
}
void debugger::write_memory(uint64_t address, uint64_t value)
{
    ptrace(PTRACE_POKEDATA, m_pid, address, value);
}
void debugger::continue_execution()
{
    step_over_breakpoint();
    ptrace(PTRACE_CONT, m_pid, nullptr, nullptr);
    wait_for_signal();
}
void debugger::set_breakpoint_at(uint64_t addr)
{
    intptr_t m_address = static_cast<intptr_t>(m_base_addr + addr);
    std::cout << "Set breakpoint at address \x1B[38;5;196m0x" << std::hex << m_address << "\x1B[0m" << std::endl;
    breakpoint bp{m_pid, m_address};
    bp.enable();
    m_breakpoints[m_address] = bp;
    for (auto const &bp : m_breakpoints)
    {
        std::cout << "Breakpoint at address \x1B[38;5;196m0x" << std::hex << bp.first << "\x1B[0m" << std::endl;
    }
}
void debugger::dump_registers()
{
    for (const auto &rd : g_register_descriptors)
    {
        std::cout << "\u001b[33m" << rd.name << "\u001b[0m\t: 0x" << std::setfill('0') << std::setw(16) << std::hex << get_register_value(m_pid, rd.r) << std::endl;
    }
}
uint64_t debugger::get_pc()
{
    return get_register_value(m_pid, reg::rip);
}
void debugger::wait_for_signal()
{
    int wait_status;
    auto options = 0;
    waitpid(m_pid, &wait_status, options);
}
void debugger::set_pc(uint64_t pc)
{
    set_register_value(m_pid, reg::rip, pc);
}
void debugger::step_over_breakpoint()
{
    auto potent_bp = get_pc() - 1;
    if (m_breakpoints.count(potent_bp))
    {
        auto &bp = m_breakpoints[potent_bp];
        if (bp.is_enabled())
        {
            auto prev_instr_addr = potent_bp;
            set_pc(prev_instr_addr);
            bp.disable();
            ptrace(PTRACE_SINGLESTEP, m_pid, nullptr, nullptr);
            wait_for_signal();
            bp.enable();
        }
    }
}
void execute_debugee(const std::string &prog_name)
{
    if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0)
    {
        std::cerr << "Ptrace unsuccessful\n";
        return;
    }
    execl(prog_name.c_str(), prog_name.c_str(), nullptr);
}

int main(int argc, char *argv[])
{
    // ptrace(ptrace_request, pid, addr, data)
    if (argc < 2)
    {
        std::cerr << "Usage: ./debugger <program>";
        return EXIT_FAILURE;
    }
    auto prog = argv[1];
    auto pid = fork();
    if (pid == 0)
    {
        personality(ADDR_NO_RANDOMIZE);
        execute_debugee(prog);
    }
    else if (pid >= 1)
    {
        std::cout << "Started debugging process " << pid << '\n';
        std::string command = "cat /proc/" + std::to_string(pid) + "/maps| sed -n '1{s/^\\([^ -]*\\).*/\\1/p}'";
        FILE *pipe = popen(command.c_str(), "r");
        if (!pipe)
        {
            std::cerr << "Error: Failed to run the command\n";
            return EXIT_FAILURE;
        }
        char buffer[256];
        std::string addr;
        if (fgets(buffer, 256, pipe) != nullptr)
        {
            addr = buffer;
            addr.erase(std::remove(addr.begin(), addr.end(), '\n'), addr.end());
        }
        pclose(pipe);
        std::cout << "Entry point: 0x" << addr << std::endl;
        uint64_t entry_point = std::stoul(addr, 0, 16);
        debugger dbg{prog, pid, entry_point};
        dbg.set_breakpoint_at(0);
        dbg.run();
    }
}