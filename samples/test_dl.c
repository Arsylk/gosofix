#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>

typedef char* (*FixElfFunc)(const char*, unsigned long long, const char*);

int main(int argc, char** argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <path_to_gosofix_so> <lib_to_fix>\n", argv[0]);
        return 1;
    }

    const char* gosofix_path = argv[1];
    const char* target_lib = argv[2];

    void* handle = dlopen(gosofix_path, RTLD_LAZY);
    if (!handle) {
        fprintf(stderr, "dlopen failed: %s\n", dlerror());
        return 1;
    }

    FixElfFunc fix_elf = (FixElfFunc)dlsym(handle, "FixElf");
    if (!fix_elf) {
        fprintf(stderr, "dlsym failed: %s\n", dlerror());
        dlclose(handle);
        return 1;
    }

    printf("Calling FixElf via dlsym...\n");
    char* msg = fix_elf(target_lib, 0, NULL);
    if (msg) {
        printf("Message from FixElf: %s\n", msg);
        free(msg); // Free the string returned by Go
    } else {
        printf("FixElf returned a null message.\n");
    }

    dlclose(handle);
    return 0;
}
