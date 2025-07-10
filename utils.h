#ifndef  _UTILS_H
#define _UTILS_H

#include "ptrace_injector.h"
#include <sys/stat.h>

// ELF analysis
unsigned long long get_func_addr(int pid, const char* lib_name, const char* func_name);
int is_control_flow_insn(cs_insn *insn);
unsigned long long get_elf_entry_point(const char* path);

// find symbol from ELF 
unsigned long long get_symbol_address(const char* path, const char* symbol_name);
void get_image_base_address(int pid, const char* target_path, unsigned long long *base_addr);
void get_target_text_segment(int pid, const char* target_path, unsigned long long *start, unsigned long long *end);
int is_pie_executable(const char* path);


#endif