#ifndef _SHARED_MEM_H
#define _SHARED_MEM_H

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/shm.h>
#include <string.h>

unsigned char * build_mem(int SHM_SIZE, char *SHM_ENV_VAR, int *id);

#endif