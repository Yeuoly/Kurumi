#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/fcntl.h>
#include <linux/memfd.h>
//syscalls
#include <sys/syscall.h>
#include <stdint.h>

int empty(int b) {
    return b;
}

int memfd_create(const char *name, unsigned int flags) {
    int fd;
    if((fd = syscall(SYS_memfd_create, name, flags)) == -1) {
        return 0;
    }
    return fd;
}

/*
elf file has already been loaded into memory, what elfloader does is to launch the elf file
including required libraries, and then exit.
*/

/*
Version 1.0
Use memfd_create to create a anynomous file, and then write the elf file into it.
at last use execve to launch the elf file.

but if the elf file requires some libraries which locate in the relative path of elf itself, it will fail.
TODO: fix this problem
*/

int LoadElf(void *mem, size_t memlen, char *argv[], char *envp[], char **err) {
    int fd = memfd_create("elfloader", 0);
    if (fd < 0) {
        *err = "memfd_create failed";
        return -1;
    }
    if (write(fd, mem, memlen) != memlen) {
        *err = "write failed";
        return -1;
    }
    if (lseek(fd, 0, SEEK_SET) != 0) {
        *err = "lseek failed";
        return -1;
    }
    //get pid
    pid_t pid = getpid();
    char elfpath [256] = { 0 };
    sprintf(elfpath, "/proc/%d/fd/%d", pid, fd);

    //execve
    if (execve(elfpath, argv, envp) < 0) {
        *err = "execve failed";
        return -1;
    }

    return 0;
}