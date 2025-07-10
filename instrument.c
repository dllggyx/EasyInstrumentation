#include "instrument.h"
#include "log.h"
#include "shared_mem.h"
#include <errno.h>


#define SHM_SIZE (1 << 16)
#define SHM_ENV_VAR "__TRACER_SHM_ID"

// Should detailed tracking information be output
// 是否输出详细的跟踪信息
int g_verbose_output = 0; 
// Should the memory space outside the target program (such as libc) be tracked
// 是否跟踪目标程序之外的内存空间（如libc）
int g_trace_all_memory = 0; 


unsigned char *__global_mem_area_ptr;

void print_usage(const char* prog_name);

// Core formula for AFL-gcc edge-coverage
// 这就是 AFL 边覆盖的核心公式
void instrument_edge(unsigned long long prev_loc_long, unsigned long long cur_loc_long) {
    
    unsigned int edge_id = (prev_loc_long >> 1) ^ cur_loc_long;
    // Ensure the index is within the 64KB range.
    // 确保索引在 64KB 范围内
    edge_id %= SHM_SIZE; 

    LOG_VERBOSE("[Target] Trigger edge: (prev:%d -> cur:%d). Hash index: %u\n", prev_loc_long, cur_loc_long, edge_id);
    // Add one at the corresponding position in the shared memory.
    // 在共享内存的对应位置上加一
    __global_mem_area_ptr[edge_id]++; 
}




int main(int argc, char *argv[]) {

    int opt;
    while ((opt = getopt(argc, argv, "vah")) != -1) {
        switch (opt) {
            case 'v':
                g_verbose_output = 1;
                break;
            case 'a':
                g_trace_all_memory = 1;
                break;
            case 'h':
                print_usage(argv[0]);
                return 1;
            default: /* '?' */
                print_usage(argv[0]);
                return 1;
        }
    }

    if(optind >= argc) {
        fprintf(stderr, "Error: Missing program to trace.\n");
        print_usage(argv[0]);
        return 1;
    }
    
    char* target_path = argv[optind];

    // Prapare shared memory start
    int shm_id = 0;
    __global_mem_area_ptr = build_mem(SHM_SIZE, SHM_ENV_VAR, &shm_id);

    pid_t child_pid = fork();

    if (child_pid == 0) {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execv(target_path, &argv[optind]);
        perror("execv");
        exit(1);
    } else if (child_pid > 0) {
        int status;
        // wait for SIGTRAP
        // 等待初始的SIGTRAP
        waitpid(child_pid, &status, 0);
        if (!WIFSTOPPED(status)) {
            fprintf(stderr, "Child did not stop as expected.\n");
            return 1;
        }
        LOG_VERBOSE("[Tracer] Victim process %d stopped. Starting injection.\n", child_pid);


        int is_pie = is_pie_executable(target_path);


        unsigned long long base_addr = 0;
        unsigned long long main_addr = 0;
        int attempts = 0;
        const int max_attempts = 100; // Wait for max 1 second (100 * 10ms)
        do {
            get_image_base_address(child_pid, target_path, &base_addr);
            if (base_addr != 0) break;
            usleep(10000); // Wait 10ms between attempts
            attempts++;
        } while (attempts < max_attempts);
        if (base_addr == 0 && is_pie) {
            fprintf(stderr, "[Tracer] Failed to get target runtime base address. Aborting.\n");
            kill(child_pid, SIGKILL);
            return 1;
        }
        LOG_VERBOSE("[Tracer] Target runtime base address is at 0x%llx\n", base_addr);


        // Get the entry point from the ELF header instead of searching for the 'main' symbol.
        // 从ELF头获取入口点，而不是搜索 'main' 符号.
        unsigned long long entry_point_offset = get_elf_entry_point(target_path);
        if (entry_point_offset == 0) {
            fprintf(stderr, "[Tracer] Failed to get entry point for %s\n", target_path);
            kill(child_pid, SIGKILL);
            return 1;
        }
        main_addr = base_addr + entry_point_offset;


        if (is_pie) {
            // PIE file
            // unsigned long long main_offset = get_symbol_address(target_path, "main");
            
            // if (main_offset == 0) {
            //     fprintf(stderr, "[Tracer] Failed to get 'main' symbol offset for PIE.\n");
            //     kill(child_pid, SIGKILL); return 1;
            // }
            // main_addr = base_addr + main_offset;
            // LOG_VERBOSE("[Tracer] 'main' symbol offset is 0x%llx\n", main_offset);
            main_addr = base_addr + entry_point_offset;

        } else {
            // non-PIE file
            main_addr = entry_point_offset;
            if (main_addr == 0) {
                fprintf(stderr, "[Tracer] Failed to get 'main' absolute address for non-PIE.\n");
                kill(child_pid, SIGKILL); return 1;
            }
        }


        /** ========= initiate Capstone start ========== **/

        struct user_regs_struct regs;
        csh handle; // Capstone handle
        cs_insn *insn; // Capstone instruction object
        size_t count;

        // initiate Capstone
        if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
            fprintf(stderr, "Failed to initialize capstone\n");
            return -1;
        }
        // Open detailed information to obtain the instruction set.
        // 开启详细信息以获取指令组
        cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON); 

        /** ========= initiate Capstone end ========== **/



        LOG_VERBOSE("[Tracer] Attempting to set breakpoint at calculated address: 0x%llx\n", main_addr);

        errno = 0; // Clear errno before the ptrace call
        long original_code = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)main_addr, NULL);
        if (errno != 0) {
            perror("[Tracer] ptrace PEEKTEXT failed");
            fprintf(stderr, "[Tracer] Could not read from address 0x%llx. Is it valid?\n", main_addr);
            kill(child_pid, SIGKILL);
            return 1;
        }

        // Set a breakpoint (0xCC) at the entry point
        // 在入口点设置断点 (0xCC)
        long trap_code = (original_code & ~0xFF) | 0xCC;
        if (ptrace(PTRACE_POKETEXT, child_pid, (void*)main_addr, (void*)trap_code) == -1) {
            perror("[Tracer] ptrace POKETEXT failed");
            fprintf(stderr, "[Tracer] Could not write breakpoint to address 0x%llx.\n", main_addr);
            kill(child_pid, SIGKILL);
            return 1;
        }
        LOG_VERBOSE("[Tracer] Breakpoint (0xCC) successfully written at 0x%llx.\n", main_addr);

        // Let the child process continue running until it hits the breakpoint we set in main.
        // 让子进程继续运行，直到命中我们在 main 的断点
        if (ptrace(PTRACE_CONT, child_pid, NULL, NULL) == -1) {
            perror("[Tracer] ptrace CONT failed");
            kill(child_pid, SIGKILL);
            return 1;
        }


        unsigned long long text_start = 0, text_end = 0;
        get_target_text_segment(child_pid, target_path, &text_start, &text_end);

        LOG_VERBOSE("[Tracer] Target text segment from 0x%llx to 0x%llx\n", text_start, text_end);


        // wait for SIGTRAP
        waitpid(child_pid, &status, 0);

        unsigned long long prev_block_addr = 0;

        if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
            LOG_VERBOSE("[Tracer] Breakpoint at 'main' hit. Proceeding with SHM injection.\n");
            
            // Restore the original instruction of the main entry and rewind the RIP to the beginning of the instruction.
            // 恢复 main 入口的原始指令，并将 RIP 回退到指令开始处
            ptrace(PTRACE_POKETEXT, child_pid, (void*)main_addr, (void*)original_code);
            struct user_regs_struct regs;
            ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
            regs.rip = main_addr;
            ptrace(PTRACE_SETREGS, child_pid, NULL, &regs);

            // find function address from libc
            // 找到libc中所需函数的地址，从而为共享内存做准备
            unsigned long long getenv_addr = get_func_addr(child_pid, "libc.so", "getenv");
            unsigned long long atoi_addr   = get_func_addr(child_pid, "libc.so", "atoi");
            unsigned long long shmat_addr  = get_func_addr(child_pid, "libc.so", "shmat");
            unsigned long long mmap_addr = get_func_addr(child_pid, "libc.so", "mmap");
            if (!getenv_addr || !atoi_addr || !shmat_addr || !mmap_addr) {
                fprintf(stderr, "[Tracer] Failed to resolve function addresses in victim.\n");
                kill(child_pid, SIGKILL);
                return 1;
            }
            LOG_VERBOSE("[Tracer] Resolved addresses: getenv=0x%llx, atoi=0x%llx, shmat=0x%llx\n",
                getenv_addr, atoi_addr, shmat_addr);


            // Allocate memory in the target program to store string parameters.
            // 在target中分配内存用于存放字符串参数
            unsigned long long remote_mem = remote_call(child_pid, mmap_addr,
                                                        0, 4096, PROT_READ | PROT_WRITE, 
                                                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            

            if(remote_mem == (unsigned long long)-1 || remote_mem == 0) {
                fprintf(stderr, "[Tracer] mmap failed in [%s].\n", target_path);
                kill(child_pid, SIGKILL);
                return 1;
            }
            LOG_VERBOSE("[Tracer] Allocated remote memory in [%s] at: 0x%llx\n", target_path, remote_mem);
            // Write the environment variable name into the target program's memory.
            // 将环境变量名写入target program内存
            ptrace_write(child_pid, remote_mem, (void*)SHM_ENV_VAR, strlen(SHM_ENV_VAR) + 1);


            // --- Start Injecting ---

            // Call getenv(SHM_ENV_VAR)
            // 调用 getenv(SHM_ENV_VAR)
            unsigned long long shm_id_str_ptr = remote_call(child_pid, getenv_addr, remote_mem, 0,0,0,0,0);
            if (!shm_id_str_ptr) {
                fprintf(stderr, "[Tracer] getenv returned NULL in [%s].\n", target_path);
                kill(child_pid, SIGKILL);
                return 1;
            }
            LOG_VERBOSE("[Tracer] getenv returned remote pointer: 0x%llx\n", shm_id_str_ptr);

            // Call atoi(shm_id_str_ptr)
            // 调用 atoi(shm_id_str_ptr)
            int victim_shm_id = (int)remote_call(child_pid, atoi_addr, shm_id_str_ptr, 0,0,0,0,0);
            LOG_VERBOSE("[Tracer] atoi returned SHM ID: %d\n", victim_shm_id);

            // Call shmat(victim_shm_id, NULL, 0)
            // 调用 shmat(victim_shm_id, NULL, 0)
            unsigned long long afl_area_ptr = remote_call(child_pid, shmat_addr, victim_shm_id, 0,0,0,0,0);
            if (afl_area_ptr == (unsigned long long)-1) {
                fprintf(stderr, "[Tracer] shmat failed in [%s].\n", target_path);
                kill(child_pid, SIGKILL);
                return 1;
            }
            LOG_VERBOSE("[Tracer] Injection successful! [%s] attached to SHM at 0x%llx\n", target_path, afl_area_ptr);


            while (WIFSTOPPED(status)) {

                ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
                
                // Check if the current RIP is the entry of a new basic block.
                // // 检查当前 RIP 是否是一个新的基本块入口
                if (g_trace_all_memory || (regs.rip >= text_start && regs.rip < text_end)) {

                    LOG_VERBOSE("[Tracer] >> New Basic Block detected at: 0x%llx\n", regs.rip);
                    
                    // Step through until finding the end of the basic block.
                    // 单步执行直到找到基本块的末尾
                    unsigned long long current_rip = regs.rip;
                    instrument_edge(prev_block_addr, current_rip);
                    prev_block_addr = current_rip;
                    while (1) {
                        // Read the machine code of the current instruction (up to 15 bytes, maximum length of x86 instruction)
                        // 读取当前指令的机器码 (最多15字节，x86指令最大长度)
                        unsigned char code[15];
                        for(int i=0; i < sizeof(code); i+= sizeof(long)) {
                            *(long*)(code + i) = ptrace(PTRACE_PEEKTEXT, child_pid, current_rip + i, NULL);
                        }
                        
                        // Capstone disassembly
                        // 使用Capstone反汇编
                        count = cs_disasm(handle, code, sizeof(code), current_rip, 1, &insn);
                        if (count > 0) {
                            if (is_control_flow_insn(insn)) {
                                cs_free(insn, count);
                                break; 
                            }
                            cs_free(insn, count);
                        } else {
                            fprintf(stderr, "Failed to disassemble code at 0x%llx\n", current_rip);
                            break;
                        }

                        // execute single instruction
                        // 单步执行一条指令
                        ptrace(PTRACE_SINGLESTEP, child_pid, NULL, NULL);
                        waitpid(child_pid, &status, 0);
                        if (!WIFSTOPPED(status)) break; 
                        // update RIP
                        // 更新 RIP
                        struct user_regs_struct step_regs;
                        ptrace(PTRACE_GETREGS, child_pid, NULL, &step_regs);
                        current_rip = step_regs.rip;
                    }
                }
                else{
                    // LOG_VERBOSE("[Tracer] >> Skip other code space.\n");
                }
                    
                if (!WIFSTOPPED(status)) {
                    break; 
                }
                
                // to execute the next code block
                if (ptrace(PTRACE_SINGLESTEP, child_pid, NULL, NULL) < 0) {
                    perror("ptrace_singlestep");
                    break;
                }
                waitpid(child_pid, &status, 0);

            }
        } else {
             fprintf(stderr, "[Tracer] Did not stop at the expected breakpoint. Checking child status...\n");
             // Add detailed status reporting to understand WHY it didn't stop.
             if (WIFEXITED(status)) {
                 fprintf(stderr, "[Tracer] Child process exited normally with status %d.\n", WEXITSTATUS(status));
             } else if (WIFSIGNALED(status)) {
                 fprintf(stderr, "[Tracer] Child process was terminated by signal %d.\n", WTERMSIG(status));
             } else {
                 fprintf(stderr, "[Tracer] Child is in an unexpected state: status=0x%x\n", status);
             }
        }

        LOG_VERBOSE("[Tracer] >> Victim process finished.\n");
        cs_close(&handle);


        // read result
        int non_zero_bytes = 0;
        for (int i = 0; i < SHM_SIZE; i++) {
            if (__global_mem_area_ptr[i] != 0) {
                non_zero_bytes++;
                LOG_VERBOSE("[Tracer] New coverage found at index %d, value is %u\n", i, __global_mem_area_ptr[i]);
            }
        }
        printf("[Tracer] Analysis completed, a total of %d new coverage points are found.\n", non_zero_bytes);


        // delete shared memory
        shmdt(__global_mem_area_ptr);
        shmctl(shm_id, IPC_RMID, NULL);
        LOG_VERBOSE("[Tracer] Clean and Exit. \n");

    } else {
        perror("fork");
        return 1;
    }

    return 0;
}

void print_usage(const char* prog_name) {
    fprintf(stderr, "Usage: %s [-v] [-a] [-h] <program_to_trace> [args_for_program...]\n", prog_name);
    fprintf(stderr, "  -h: Print help information.\n");
    fprintf(stderr, "  -v: Verbose mode. Prints detailed tracing information.\n");
    fprintf(stderr, "  -a: Trace all memory. Traces inside shared libraries (like libc), not just the main program. (Warning: may fail)\n");
}