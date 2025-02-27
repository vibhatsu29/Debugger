#include <iostream>
#include <capstone/capstone.h>
#include <elf/elf++.hh>
#include <fcntl.h>
#include <string>
#include "helper.hpp"
namespace mydbg
{
    class disassember
    {
    public:
        disassember(std::string m_prog_name) { m_prog = m_prog_name; }
        void disassemble(const uint8_t *code, size_t code_size, uint64_t address)
        {
            csh handle;
            cs_insn *insn;
            size_t count;

            if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
            {
                std::cerr << "Failed to initialize Capstone" << std::endl;
                return;
            }
            std::cout << "Raw function code: ";
            for (size_t i = 0; i < code_size; ++i)
            {
                printf("%02x ", code[i]);
            }
            std::cout << std::endl;

            count = cs_disasm(handle, code, code_size, 0x1000, 0, &insn);
            std::cout << "count=" << count << std::endl;
            if (count > 0)
            {
                for (size_t i = 0; i < count; i++)
                {
                    printf("0x%" PRIx64 ":\t%s\t\t%s\n", insn[i].address, insn[i].mnemonic, insn[i].op_str);
                }
                cs_free(insn, count);
            }
            else
            {
                std::cerr << "Failed to disassemble given code!" << std::endl;
            }

            cs_close(&handle);
        }
        func_data get_func(std::string function_name)
        {
            int fd = open(m_prog.c_str(), O_RDONLY);
            if (fd < 0)
            {
                std::cerr << "Failed to open ELF file\n";
                return func_data{};
            }
            elf::elf ef(elf::create_mmap_loader(fd));
            uint64_t base_address = -1;
            for (const auto &seg : ef.segments())
            {
                if (seg.get_hdr().type == elf::pt::load)
                {
                    base_address = seg.get_hdr().vaddr;
                    break;
                }
            }
            for (const auto &sec : ef.sections())
            {
                if (sec.get_hdr().type == elf::sht::symtab)
                {
                    for (const auto &sym : sec.as_symtab())
                    {
                        if (sym.get_data().type() == elf::stt::func && sym.get_name() == function_name.c_str())
                        {
                            uint64_t func_addr = sym.get_data().value;
                            uint64_t func_size = sym.get_data().size;

                            auto text_sc = ef.get_section(".text");

                            uint64_t section_addr = text_sc.get_hdr().addr;
                            uint64_t section_offset = text_sc.get_hdr().offset;
                            uint64_t section_size = text_sc.get_hdr().size;

                            if (func_addr >= section_addr && func_addr < section_addr + section_size)
                            {

                                uint64_t func_offset_in_section = func_addr - section_addr;

                                const auto &data = text_sc.data();
                                const uint8_t *func_code = reinterpret_cast<const uint8_t *>(data) + func_offset_in_section;
                                func_data func{func_code, func_size, base_address + func_addr};
                                return func;
                            }
                        }
                    }
                }
            }
            std::cerr << "Function not found!" << std::endl;
            return func_data{};
        }

    private:
        std::string m_prog;
    };
}