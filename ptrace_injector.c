#include "ptrace_injector.h"


// x86_64: syscall; ret;
unsigned char syscall_code[] = { 0x0f, 0x05, 0xc3 };

unsigned long long remote_call(int pid, unsigned long long func_addr, 
                               unsigned long long rdi, unsigned long long rsi, 
                               unsigned long long rdx, unsigned long long rcx,
                               unsigned long long r8, unsigned long long r9) {
    struct user_regs_struct old_regs, regs;
    

    //restore regs
    // 保存现场
    ptrace(PTRACE_GETREGS, pid, NULL, &old_regs);
    memcpy(&regs, &old_regs, sizeof(regs));


    // Set function call parameters
    // 设置函数调用参数
    regs.rdi = rdi;
    regs.rsi = rsi;
    regs.rdx = rdx;
    regs.rcx = rcx; 
    regs.r8  = r8;  
    regs.r9  = r9;  
    // Point to the function to be called
    // 指向要调用的函数
    regs.rip = func_addr; 

    // Forge a return address on the stack. We use an illegal address, 
    // so when the function returns, it will trigger SIGSEGV, allowing us to regain control.
    // 在栈上伪造一个返回地址。我们用一个非法地址，这样函数返回时会触发SIGSEGV，这样我们就能重新获得控制权
    regs.rsp -= 8;
    unsigned long long fake_ret_addr = 0xDEADBEEF;
    ptrace_write(pid, regs.rsp, &fake_ret_addr, sizeof(fake_ret_addr));
    
    // Set the register and continue execution
    // 设置寄存器并继续执行
    ptrace(PTRACE_SETREGS, pid, NULL, &regs);
    ptrace(PTRACE_CONT, pid, NULL, NULL);

    // SIGSEGV triggered when waiting for the function to return.
    // 等待函数返回时触发的SIGSEGV
    int status;
    waitpid(pid, &status, 0);

    if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGSEGV) {
        // Obtain the return value and restore regs.
        // 6. 获取返回值并恢复现场
        ptrace(PTRACE_GETREGS, pid, NULL, &regs);
        if (regs.rip != fake_ret_addr) { 
             fprintf(stderr, "Stopped at unexpected location: 0x%llx\n", regs.rip);
        }

        unsigned long long retval = regs.rax; // return value
        ptrace(PTRACE_SETREGS, pid, NULL, &old_regs); // restore all regs
        return retval;
    } else {
        fprintf(stderr, "[Tracer] remote_call failed: Victim did not stop with SIGSEGV.\n");
        if (WIFEXITED(status)) {
            fprintf(stderr, "Victim exited with status %d\n", WEXITSTATUS(status));
        } else if (WIFSIGNALED(status)) {
            fprintf(stderr, "Victim was terminated by signal %d\n", WTERMSIG(status));
        } else if (WIFSTOPPED(status)) {
            fprintf(stderr, "Victim was stopped by signal %d\n", WSTOPSIG(status));
        }
        return -1;
    }
}


/** @brief Read data from the memory of the traced process 
 * @param pid PID of the traced process 
 * @param addr Remote memory address to read from
 * @param data Local buffer to store the read data 
 * @param len Number of bytes to read
 */
void ptrace_read(int pid, unsigned long long addr, void *data, size_t len) {
    size_t i = 0;
    long word;
    char *ptr = (char *)data;

    // Read in a way aligned by bytes (8 bytes)
    // 按字（8字节）对齐的方式读取
    for (i = 0; i < len / sizeof(long); i++) {
        word = ptrace(PTRACE_PEEKDATA, pid, addr + i * sizeof(long), NULL);
        if (word == -1) {
            perror("ptrace_peekdata");
        }
        memcpy(ptr + i * sizeof(long), &word, sizeof(long));
    }

    // Processing the remaining part that is less than one character.
    // 处理剩余的不足一个字的部分
    if (len % sizeof(long) != 0) {
        word = ptrace(PTRACE_PEEKDATA, pid, addr + i * sizeof(long), NULL);
        if (word == -1) {
            perror("ptrace_peekdata");
        }
        memcpy(ptr + i * sizeof(long), &word, len % sizeof(long));
    }
}

/** @brief Write data into the memory of the traced process 
 * @param pid The PID of the traced process 
 * @param addr The remote memory address to write to 
 * @param data The local buffer containing the data to be written 
 * @param len The number of bytes to write
 */
void ptrace_write(int pid, unsigned long long addr, void *data, size_t len) {
    size_t i = 0;
    long word;
    char *ptr = (char *)data;

    // Write in a way aligned by bytes (8 bytes)
    // 按字（8字节）对齐的方式写入
    for (i = 0; i < len / sizeof(long); i++) {
        memcpy(&word, ptr + i * sizeof(long), sizeof(long));
        if (ptrace(PTRACE_POKEDATA, pid, addr + i * sizeof(long), word) == -1) {
            perror("ptrace_pokedata");
        }
    }

    // Processing the remaining part that is less than one character.
    // 处理剩余的不足一个字的部分
    if (len % sizeof(long) != 0) {
        // For the incomplete characters at the end, the original data needs to be read first, 
        // and then our data can overwrite some bytes. This can avoid damaging the adjacent data.
        // 对于最后不完整的字，需要先读取原始数据，再用我们的数据覆盖部分字节
        // 这样可以避免破坏相邻的数据
        word = ptrace(PTRACE_PEEKDATA, pid, addr + i * sizeof(long), NULL);
        if (word == -1) {
            perror("ptrace_peekdata for write");
        }
        memcpy(&word, ptr + i * sizeof(long), len % sizeof(long));
        if (ptrace(PTRACE_POKEDATA, pid, addr + i * sizeof(long), word) == -1) {
            perror("ptrace_pokedata");
        }
    }
}