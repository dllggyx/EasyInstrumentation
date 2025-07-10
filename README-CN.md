# EasyInstrumentation


**EasyInstrumentation**是一个基于`ptrace`的动态二进制插桩工具，旨在演示如何实现对一个目标程序进行跟踪与动态插桩，并实现类似于`afl-as`的边覆盖信息统计。它无需对目标程序进行任何源码修改或预编译，即可在运行时分析其执行路径。

## 核心功能
1. 运行时代码注入
2. 统计目标程序的边覆盖信息
3. 指令实时反汇编

## Environment
在基于 Debian/Ubuntu 的系统上，您需要安装 build-essential 和 libcapstone-dev 来满足编译需求。
```bash
sudo apt-get update
sudo apt-get install build-essential libcapstone-dev
```

## How to use
你可以使用如下命令来对我们准备好的程序`victim`进行插桩：
```bash
make
./instrument victim
```
你也可以对别的二进制文件做插桩，例如可以对/bin/ls做插桩,使用`-v`可以显示详细信息：
```bash
./instrument -v /bin/ls
```
你可以在运行时使用以下参数的组合来控制 instrument 工具的行为。
|Parameter|Description|
|:-:|:-|
|-h|**帮助 (Help)**: 打印此帮助信息并退出。|
|-a|**跟踪全部 (Trace All)**: 跟踪所有内存区域的代码执行，包括共享库（如 libc.so）。默认情况下，工具只跟踪主程序 .text 段内的代码。 警告: 此选项会极大降低运行速度，并可能因进入复杂的库代码而导致跟踪失败或行为异常。|
|-v|**详细模式 (Verbose Mode)**: 打印详细的跟踪日志。这对于调试工具本身或深入理解其工作流程非常有用。日志内容包括：共享内存创建、基地址计算、断点设置、远程调用详情、每个基本块的入口地址以及覆盖率边的触发等。|

## 程序运行的流程
目标程序是以子进程的方式运行的，具体来说，整个程序运行流程如下：
1. 准备共享内存，获取共享内存ID
2. 父进程使用`fork()`创建子进程，子进程加载目标程序，并使用`ptrace(PTRACE_TRACEME, ...)`请求父进程追踪
3. 父进程通过解析`/proc/<pid>/maps`获取目标程序基地址，并解析ELF文件，获取`main`函数的符号地址，从而计算出`main`函数在内存中的绝对地址，父进程在此设置断点
4. 当子进程运行至断点处时，父进程在目标进程的`libc.so`中动态查找 `getenv`, `shmat`, `mmap` 等函数的地址，使用`remote_call`机制，使子进程能够访问共享内存
5. 主进程追踪子进程的代码基本块，根据基本块的入口地，使用类似于`afl-as`的方式记录边覆盖，并更新共享内存
6. 父进程遍历共享内存位图，统计被触发的边的数量
