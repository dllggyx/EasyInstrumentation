#ifndef _LOG_H
#define _LOG_H

#include <stdio.h>

// Declare an external global variable, the entity of which is defined in instrument.c.
// 声明一个外部全局变量，这个变量的实体定义在 instrument.c 中
extern int g_verbose_output;

// Define the log macro.
// 定义我们的日志宏
#define LOG_VERBOSE(...) \
    do { \
        if (g_verbose_output) { \
            printf(__VA_ARGS__); \
        } \
    } while (0)



#endif // _LOG_H