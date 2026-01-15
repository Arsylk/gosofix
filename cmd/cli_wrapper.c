/*
 * Entry point for gosofix when executed directly as a binary.
 * This file is compiled into the shared library to make it directly executable.
 * 
 * When the binary is:
 * - Executed directly: _start (from Scrt1.o) -> initialization -> main() -> runCLI()
 * - Loaded via dlopen(): runtime initialized by loader -> FixElf/runCLI available via dlsym()
 */

#include <stdlib.h>
#include <stdio.h>

// Embed the interpreter path directly so the kernel knows how to run this .so
#if defined(__ANDROID__)
    #if defined(__aarch64__)
        const char __attribute__((section(".interp"))) interp[] = "/system/bin/linker64";
    #else
        const char __attribute__((section(".interp"))) interp[] = "/system/bin/linker";
    #endif
#elif defined(__x86_64__)
    const char __attribute__((section(".interp"))) interp[] = "/lib64/ld-linux-x86-64.so.2";
#elif defined(__aarch64__)
    const char __attribute__((section(".interp"))) interp[] = "/lib/ld-linux-aarch64.so.1";
#else
    // Fallback or error - let's assume glibc x86-64 to be safe, or comment out
    const char __attribute__((section(".interp"))) interp[] = "/lib64/ld-linux-x86-64.so.2";
#endif

// Forward declaration of the Go runCLI function  
extern void runCLI(int argc, char** argv);

// Standard main entry point
// This will be called by __libc_start_main after runtime initialization
int main(int argc, char** argv) {
    runCLI(argc, argv);
    return 0;
}
