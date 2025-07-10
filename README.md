# EasyInstrumentation

**EasyInstrumentation** is a dynamic binary instrumentation tool based on ptrace, designed to demonstrate how to trace and dynamically instrument a target program, and to collect edge coverage statistics in a manner similar to `afl-as`. It can analyze a program's execution path at runtime without requiring any source code modifications or pre-compilation.

## Core Features
1. Runtime Code Injection
2. Edge Coverage Statistics
3. Real-time Instruction Disassembly

## Environment
On Debian/Ubuntu-based systems, you need to install `build-essential`` and `libcapstone-dev` to meet the compilation requirements.
```bash
sudo apt-get update
sudo apt-get install build-essential libcapstone-dev
```

## How to Use
You can use the following commands to instrument the provided victim program.
```bash
make
./instrument victim
```
You can also instrument other binaries, e.g. `/bin/ls`, and use `-v` to show the details:
```bash
./instrument -v /bin/ls
```

You can use a combination of the following parameters at runtime to control the behavior of the `instrument`.
|Parameter|Description|
|:-:|:-|
|-h|**Help**: Print this help message and exit.|
|-a|**Trace All**: Trace code execution in all memory regions, including shared libraries (e.g., libc.so). By default, the tool only traces code within the main program's .text section. Warning: This option will significantly slow down execution and may lead to tracking failures or abnormal behavior due to entering complex library code.|
|-v|**Verbose Mode**: Print detailed tracing logs. This is very useful for debugging the tool itself or for gaining a deeper understanding of its workflow. The log content includes: shared memory creation, base address calculation, breakpoint settings, remote call details, entry addresses of each basic block, and triggered coverage edges.|


## How It Works
The target program is run as a child process. Specifically, the entire program flow is as follows:

1. The parent process prepares a shared memory segment and obtains its ID.
2. The parent process uses `fork()` to create a child process. The child process loads the target program and requests to be traced by the parent using `ptrace(PTRACE_TRACEME, ...)`.
3. The parent process parses `/proc/<pid>/maps` to get the target program's base address. It then parses the ELF file to find the symbol address of the `main` function, calculating its absolute address in memory. The parent sets a breakpoint at this address.
4. When the child process hits the breakpoint, the parent process dynamically finds the addresses of functions like `getenv`, `shmat`, and `mmap` within the target process's `libc.so`. It then uses a `remote_call` mechanism to make the child process execute these functions, enabling it to access the shared memory.
5. The parent process traces the child's basic blocks. Based on the entry address of each basic block, it records edge coverage in a manner similar to `afl-as` and updates the shared memory bitmap.
6. Finally, the parent process iterates through the shared memory bitmap to count the number of triggered edges.




