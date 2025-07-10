# include "shared_mem.h"
# include "log.h"

unsigned char * build_mem(int SHM_SIZE, char *SHM_ENV_VAR, int *id){
    /**  =============== Prapare shared memory start =================   **/
    int shm_id;
    char shm_id_str[10];
    // Tracer points to the pointer of shared memory.
    unsigned char *shared_mem_ptr;

    LOG_VERBOSE("[Tracer] Start...\n");
    // Create shared memory
    // 创建共享内存
    shm_id = shmget(IPC_PRIVATE, SHM_SIZE, IPC_CREAT | 0600);
    if (shm_id < 0) {
        perror("shmget failed");
        exit(1);
    }
    LOG_VERBOSE("[Tracer] Create shared memory, ID = %d\n", shm_id);

    // Attach the shared memory segment to the address space of the Tracer itself.
    // 将共享内存段附加到 Tracer 自身的地址空间
    shared_mem_ptr = shmat(shm_id, NULL, 0);
    if (shared_mem_ptr == (void *)-1) {
        perror("shmat failed");
        exit(1);
    }
    LOG_VERBOSE("[Tracer] Shared memory has been attached to address %p\n", shared_mem_ptr);

    // Export the shared memory ID to the environment variable
    // 将共享内存ID导出到环境变量
    snprintf(shm_id_str, sizeof(shm_id_str), "%d", shm_id);
    setenv(SHM_ENV_VAR, shm_id_str, 1);
    LOG_VERBOSE("[Tracer] The SHM ID '%s' has been set to the environment variable %s.\n", shm_id_str, SHM_ENV_VAR);

    // Clean the shared memory
    // 清理共享内存
    memset(shared_mem_ptr, 0, SHM_SIZE);
    LOG_VERBOSE("[Tracer] The shared memory has been cleared, ready to start the target program...\n");
    id = &shm_id;
    return shared_mem_ptr;
    /**  =============== Prapare shared memory end =================   **/
}