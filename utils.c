#include "utils.h"


unsigned long long get_symbol_address(const char* path, const char* symbol_name) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        perror("open elf file for symbol");
        return 0;
    }

    struct stat st;
    fstat(fd, &st);
    unsigned char* mem = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (mem == MAP_FAILED) {
        perror("mmap elf file");
        close(fd);
        return 0;
    }

    Elf64_Ehdr* ehdr = (Elf64_Ehdr*)mem;
    Elf64_Shdr* shdr = (Elf64_Shdr*)(mem + ehdr->e_shoff);
    
    unsigned long long result = 0;

    // 遍历节头表
    for (int i = 0; i < ehdr->e_shnum; i++) {
        // Find symbol_name from SHT_DYNSYM and SHT_SYMTAB
        // 从动态符号表 (SHT_DYNSYM) 和静态符号表 (SHT_SYMTAB)中查找
        if (shdr[i].sh_type == SHT_SYMTAB || shdr[i].sh_type == SHT_DYNSYM) {
            Elf64_Sym* symtab = (Elf64_Sym*)(mem + shdr[i].sh_offset);
            int sym_count = shdr[i].sh_size / shdr[i].sh_entsize;
            
            // Obtain the string table associated with the symbol table
            // 获取符号表关联的字符串表
            Elf64_Shdr* strtab_shdr = &shdr[shdr[i].sh_link];
            const char* strtab = (const char*)(mem + strtab_shdr->sh_offset);

            // Traverse the symbol table
            // 遍历符号表
            for (int j = 0; j < sym_count; j++) {
                if (symtab[j].st_name != 0 && strcmp(&strtab[symtab[j].st_name], symbol_name) == 0) {

                    if (ELF64_ST_TYPE(symtab[j].st_info) == STT_FUNC) {
                        result = symtab[j].st_value;
                        munmap(mem, st.st_size);
                        close(fd);
                        return result;
                        break;
                    }

                }
            }
        }
    }
}


void get_image_base_address(int pid, const char* target_path, unsigned long long *base_addr) {
    char maps_path[128];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    FILE* fp = fopen(maps_path, "r");
    if (!fp) {
        *base_addr = 0;
        return;
    }

    char line[512];
    *base_addr = 0;

    const char* exe_name = strrchr(target_path, '/');
    if (exe_name) {
        exe_name++; // skip '/'
    } else {
        exe_name = target_path;
    }

    while (fgets(line, sizeof(line), fp)) {
        // What we are looking for is the first memory mapping that matches the target program name. 
        // For a PIE executable, this is its random load base address.
        // 我们要找的是与目标程序名称匹配的第一个内存映射。
        // 对于 PIE 可执行文件，这就是它的随机加载基地址。
        if (strstr(line, exe_name)) {
            sscanf(line, "%llx", base_addr);
            break; 
        }
    }

    fclose(fp);
}

unsigned long long get_library_base(int pid, const char* lib_name) {
    char maps_path[128];
    // libc.so.6 or libc-2.xx.so
    char actual_lib_name[256];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    FILE* fp = fopen(maps_path, "r");
    if (!fp) return 0;
    char line[512];
    unsigned long long addr = 0;
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "r-xp") && strstr(line, lib_name)) {
            sscanf(line, "%llx-", &addr);
            // analyze the actual lib name from line
            // 尝试从行中解析出实际的库文件名
            char* lib_path_start = strchr(line, '/');
            if (lib_path_start) {
                sscanf(lib_path_start, "%s", actual_lib_name);
            }
            break;
        }
    }
    fclose(fp);
    return addr;
}



unsigned long long get_func_addr(int pid, const char* lib_name, const char* func_name) {
    unsigned long long remote_base = get_library_base(pid, lib_name);
    if (!remote_base) {
        fprintf(stderr, "[Tracer] Failed to find library base for %s in victim\n", lib_name);
        return 0;
    }
    // Load the same library in our own process
    // The lib_name here might be just a partial name, such as 'libc.so', dlopen requires a more complete name, like 'libc.so.6'
    // 在我们自己的进程中加载同样的库
    // 这里的lib_name可能只是部分名称，如"libc.so"，dlopen需要更完整的名称，如"libc.so.6"
    void* self_handle = dlopen("libc.so.6", RTLD_LAZY);
    if (!self_handle) {
        perror("dlopen in tracer");
        return 0;
    }
    // Obtain the address of the function in our own process.
    // 获取函数在我们自己进程中的地址
    void* self_func_ptr = dlsym(self_handle, func_name);
    if (!self_func_ptr) {
        perror("dlsym in tracer");
        dlclose(self_handle);
        return 0;
    }
    // Get the base address of the library in our own process.
    // 获取库在我们自己进程中的基地址
    unsigned long long self_base = get_library_base(getpid(), "libc.so.6");
    if (!self_base) {
        fprintf(stderr, "[Tracer] Failed to find library base for %s in self\n", lib_name);
        dlclose(self_handle);
        return 0;
    }
    // caculate offset
    // 计算偏移量
    unsigned long long offset = (unsigned long long)self_func_ptr - self_base;
    dlclose(self_handle);
    // return the final address
    // 返回目标进程中的最终地址
    return remote_base + offset;
}


// Determine if the instruction is a control flow instruction
// 判断指令是否是控制流指令
int is_control_flow_insn(cs_insn *insn) {
    for (size_t i = 0; i < insn->detail->groups_count; i++) {
        switch (insn->detail->groups[i]) {
            case X86_GRP_JUMP:
            case X86_GRP_CALL:
            case X86_GRP_RET:
            case X86_GRP_IRET:
            case X86_GRP_INT: 
                return 1;
        }
    }
    return 0;
}


unsigned long long get_elf_entry_point(const char* path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        perror("open");
        return 0;
    }

    struct stat st;
    if (fstat(fd, &st) < 0) {
        perror("fstat");
        close(fd);
        return 0;
    }

    // Use mmap to map the file into memory, more efficiently.
    // 使用 mmap 将文件映射到内存，更高效
    unsigned char *mem = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (mem == MAP_FAILED) {
        perror("mmap");
        close(fd);
        return 0;
    }

    // Convert the memory address to an ELF header pointer.
    // 将内存地址转换为 ELF 头部指针
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)mem;
    unsigned long long entry_point = ehdr->e_entry;

    munmap(mem, st.st_size);
    close(fd);

    return entry_point;
}


void get_target_text_segment(int pid, const char* target_path, unsigned long long *start, unsigned long long *end) {
    char maps_path[128];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    FILE* fp = fopen(maps_path, "r");
    if (!fp) {
        *start = 0;
        *end = 0;
        return;
    }

    char line[512];
    *start = 0;
    *end = 0;

    // extract name
    // 从路径中提取可执行文件名
    const char* exe_name = strrchr(target_path, '/');
    if (exe_name) {
        exe_name++; // skip '/'
    } else {
        exe_name = target_path;
    }

    while (fgets(line, sizeof(line), fp)) {
        // The memory area that needs to be found is marked as r-xp (read-execute-private) and matches the target program name.
        // 要找的是标记为 r-xp (可读-可执行-私有) 且与目标程序名称匹配的内存区域
        if (strstr(line, "r-xp") && strstr(line, exe_name)) {
            sscanf(line, "%llx-%llx", start, end);
            break; 
        }
    }

    fclose(fp);
}


int is_pie_executable(const char* path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return 0; // can not open file

    Elf64_Ehdr ehdr;
    if (read(fd, &ehdr, sizeof(ehdr)) != sizeof(ehdr)) {
        close(fd);
        return 0;
    }
    close(fd);
    
    // If e_type is ET_DYN, it is a PIE executable file.
    // 如果 e_type 是 ET_DYN，它就是一个 PIE 可执行文件
    return (ehdr.e_type == ET_DYN);
}
