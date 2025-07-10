#ifndef _PTRACE_INJECTOR_H
#define _PTRACE_INJECTOR_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/reg.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/mman.h>
#include <capstone/capstone.h>
#include <fcntl.h>
#include <elf.h>
#include <dlfcn.h>
#include <signal.h>


void ptrace_read(int pid, unsigned long long addr, void *data, size_t len);
void ptrace_write(int pid, unsigned long long addr, void *data, size_t len);

// remote function call
unsigned long long remote_call(int pid, unsigned long long func_addr, 
                               unsigned long long rdi, unsigned long long rsi, 
                               unsigned long long rdx, unsigned long long rcx,
                               unsigned long long r8, unsigned long long r9);

#endif