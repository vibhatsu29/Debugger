#ifndef MYDBG_BREAKPOINT_HPP
#define MYDBG_BREAKPOINT_HPP
#include <cstdint>
#include <sys/ptrace.h>

namespace mydbg
{
    class breakpoint
    {
    public:
        breakpoint() : m_pid{}, m_addr{}, m_enabled{}, m_saved_data{} {}
        breakpoint(pid_t pid, std::intptr_t addr) : m_pid{pid}, m_addr{addr}, m_enabled{false}, m_saved_data{} {}
        void enable()
        {
            auto data = ptrace(PTRACE_PEEKDATA, m_pid, m_addr, nullptr);
            std::cout << "original_data: " << std::hex << data << std::endl;
            m_saved_data = static_cast<uint8_t>(data & 0xff);
            uint64_t int3 = 0xcc;
            uint64_t data_with_int3 = (data & ~0xff | int3);
            std::cout << "data_with_int3: " << std::hex << data_with_int3 << std::endl;
            ptrace(PTRACE_POKEDATA, m_pid, m_addr, data_with_int3);
            m_enabled = true;
        }

        void disable()
        {
            uint16_t data_with_int3 = ptrace(PTRACE_PEEKDATA, m_pid, m_addr, nullptr);
            std::cout << "data_with_int3: " << std::hex << data_with_int3 << std::endl;
            uint64_t data = (data_with_int3 & ~0xff) | m_saved_data;
            std::cout << "data: " << std::hex << data << std::endl;
            ptrace(PTRACE_POKEDATA, m_pid, m_addr, data);
            m_enabled = false;
        }
        auto is_enabled() const -> bool { return m_enabled; }
        auto get_address() const -> std::intptr_t { return m_addr; }

    private:
        pid_t m_pid;
        std::intptr_t m_addr;
        bool m_enabled;
        uint8_t m_saved_data;
    };
}
#endif