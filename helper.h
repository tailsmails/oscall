#ifndef HELPER_H
#define HELPER_H

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <setjmp.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <sys/syscall.h>
#include <elf.h>

#ifndef NT_PRSTATUS
#define NT_PRSTATUS 1
#endif

#ifndef NT_PRFPREG
#define NT_PRFPREG 2
#endif

#ifndef NT_ARM_VFP
#define NT_ARM_VFP 0x400
#endif

#if defined(__aarch64__)
struct local_user_pt_regs {
    uint64_t regs[31];
    uint64_t sp;
    uint64_t pc;
    uint64_t pstate;
};
struct local_user_fpsimd_struct {
    uint64_t vregs[32][2];
    uint32_t fpsr;
    uint32_t fpcr;
    uint32_t __pad;
};
#elif defined(__x86_64__)
struct local_user_regs_struct {
    uint64_t r15, r14, r13, r12, rbp, rbx, r11, r10;
    uint64_t r9, r8, rax, rcx, rdx, rsi, rdi, orig_rax;
    uint64_t rip, cs, eflags, rsp, ss, fs_base, gs_base, ds, es, fs, gs;
};
struct local_user_fpregs_struct {
    uint16_t cwd, swd, ftw, fop;
    uint64_t rip, rdp;
    uint32_t mxcsr, mxcsr_mask;
    uint32_t st_space[32];
    uint32_t xmm_space[64];
    uint32_t padding[24];
};
#elif defined(__arm__)
struct local_pt_regs {
    long uregs[18];
};
#define ARM_r0 uregs[0]
#define ARM_sp uregs[13]
#define ARM_lr uregs[14]
#define ARM_pc uregs[15]
#define ARM_cpsr uregs[16]
struct local_user_vfp {
    uint64_t fpregs[32];
    uint32_t fpscr;
};
#elif defined(__i386__)
struct local_user_regs_struct_32 {
    long ebx, ecx, edx, esi, edi, ebp, eax, xds, xes, xfs, xgs, orig_eax, eip, xcs, eflags, esp, xss;
};
#endif

#ifndef __NR_process_vm_readv
#if defined(__aarch64__)
#define __NR_process_vm_readv 270
#define __NR_process_vm_writev 271
#elif defined(__arm__)
#define __NR_process_vm_readv 376
#define __NR_process_vm_writev 377
#elif defined(__x86_64__)
#define __NR_process_vm_readv 310
#define __NR_process_vm_writev 311
#elif defined(__i386__)
#define __NR_process_vm_readv 347
#define __NR_process_vm_writev 348
#endif
#endif

static sigjmp_buf g_jump_buf;

static inline void v_segfault_handler(int sig) {
    (void)sig;
    siglongjmp(g_jump_buf, 1);
}

static inline int safe_sigsetjmp(void) {
    return sigsetjmp(g_jump_buf, 1);
}

static inline int write_remote_mem(pid_t pid, uintptr_t dst, const void *src, size_t len) {
    struct iovec local = { (void *)src, len };
    struct iovec remote = { (void *)dst, len };
#if defined(__NR_process_vm_writev)
    if (syscall(__NR_process_vm_writev, pid, &local, 1UL, &remote, 1UL, 0UL) == (ssize_t)len) {
        return 0;
    }
#endif
    size_t words = (len + sizeof(long) - 1) / sizeof(long);
    const long *p = (const long *)src;
    for (size_t i = 0; i < words; ++i) {
        if (ptrace(PTRACE_POKEDATA, pid, (void *)(dst + i * sizeof(long)), (void *)p[i]) == -1) {
            return -1;
        }
    }
    return 0;
}

static inline int read_remote_mem(pid_t pid, void *dst, uintptr_t src, size_t len) {
    struct iovec local = { dst, len };
    struct iovec remote = { (void *)src, len };
#if defined(__NR_process_vm_readv)
    if (syscall(__NR_process_vm_readv, pid, &local, 1UL, &remote, 1UL, 0UL) == (ssize_t)len) {
        return 0;
    }
#endif
    size_t words = (len + sizeof(long) - 1) / sizeof(long);
    long *p = (long *)dst;
    for (size_t i = 0; i < words; ++i) {
        errno = 0;
        long val = ptrace(PTRACE_PEEKDATA, pid, (void *)(src + i * sizeof(long)), NULL);
        if (val == -1 && errno) {
            return -1;
        }
        p[i] = val;
    }
    return 0;
}

static inline uintptr_t get_remote_module_base(pid_t pid, const char *module_name) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE *fp = fopen(path, "r");
    if (!fp) return 0;

    char line[512];
    uintptr_t base = 0;
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, module_name)) {
            base = (uintptr_t)strtoull(line, NULL, 16);
            break;
        }
    }
    fclose(fp);
    return base;
}

static inline uintptr_t remote_call_arch(pid_t pid, uintptr_t func_addr, int argc, uintptr_t *argv, int is_fp) {
    int status;
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        return (uintptr_t)-1;
    }
    waitpid(pid, &status, WUNTRACED);

#if defined(__aarch64__)
    struct local_user_pt_regs regs, orig_regs;
    struct local_user_fpsimd_struct fpsimd, orig_fpsimd;
    struct iovec iov = { &regs, sizeof(regs) };
    struct iovec orig_iov = { &orig_regs, sizeof(orig_regs) };
    struct iovec fp_iov = { &fpsimd, sizeof(fpsimd) };
    struct iovec orig_fp_iov = { &orig_fpsimd, sizeof(orig_fpsimd) };

    if (ptrace(PTRACE_GETREGSET, pid, (void *)NT_PRSTATUS, &iov) == -1) goto fail;
    memcpy(&orig_regs, &regs, sizeof(regs));

    int has_fp = (ptrace(PTRACE_GETREGSET, pid, (void *)NT_PRFPREG, &fp_iov) == 0);
    if (has_fp) {
        memcpy(&orig_fpsimd, &fpsimd, sizeof(fpsimd));
        for (int i = 0; i < argc && i < 8; ++i) {
            fpsimd.vregs[i][0] = argv[i];
            fpsimd.vregs[i][1] = 0;
        }
        fp_iov.iov_len = sizeof(fpsimd);
        ptrace(PTRACE_SETREGSET, pid, (void *)NT_PRFPREG, &fp_iov);
    }

    uintptr_t sp = regs.sp;
    sp = (sp - 2048) & ~0xF;

    for (int i = 0; i < argc && i < 8; ++i) {
        regs.regs[i] = argv[i];
    }
    if (argc > 8) {
        int stack_args = argc - 8;
        sp -= stack_args * sizeof(uintptr_t);
        sp &= ~0xF;
        write_remote_mem(pid, sp, &argv[8], stack_args * sizeof(uintptr_t));
    }

    regs.sp = sp;
    regs.regs[30] = 0;
    regs.pc = func_addr;

    if (ptrace(PTRACE_SETREGSET, pid, (void *)NT_PRSTATUS, &iov) == -1) goto fail;
    if (ptrace(PTRACE_CONT, pid, NULL, NULL) == -1) goto fail;

    waitpid(pid, &status, WUNTRACED);

    if (ptrace(PTRACE_GETREGSET, pid, (void *)NT_PRSTATUS, &iov) == -1) goto fail;
    uintptr_t ret_val = regs.regs[0];

    if (has_fp) {
        fp_iov.iov_len = sizeof(fpsimd);
        if (ptrace(PTRACE_GETREGSET, pid, (void *)NT_PRFPREG, &fp_iov) == 0) {
            if (is_fp) {
                ret_val = fpsimd.vregs[0][0];
            }
        }
        orig_fp_iov.iov_len = sizeof(orig_fpsimd);
        ptrace(PTRACE_SETREGSET, pid, (void *)NT_PRFPREG, &orig_fp_iov);
    }

    ptrace(PTRACE_SETREGSET, pid, (void *)NT_PRSTATUS, &orig_iov);
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    return ret_val;

#elif defined(__x86_64__)
    struct local_user_regs_struct regs, orig_regs;
    struct local_user_fpregs_struct fpregs, orig_fpregs;

    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1) goto fail;
    memcpy(&orig_regs, &regs, sizeof(regs));

    int has_fp = (ptrace(PTRACE_GETFPREGS, pid, NULL, &fpregs) == 0);
    if (has_fp) {
        memcpy(&orig_fpregs, &fpregs, sizeof(fpregs));
        for (int i = 0; i < argc && i < 8; ++i) {
            memcpy(&fpregs.xmm_space[i * 4], &argv[i], sizeof(uint64_t));
        }
        ptrace(PTRACE_SETFPREGS, pid, NULL, &fpregs);
    }

    uintptr_t sp = regs.rsp;
    sp = (sp - 2048) & ~0xF;

    uintptr_t dummy_ret = 0;
    sp -= sizeof(uintptr_t);
    write_remote_mem(pid, sp, &dummy_ret, sizeof(uintptr_t));

    if (argc > 0) regs.rdi = argv[0];
    if (argc > 1) regs.rsi = argv[1];
    if (argc > 2) regs.rdx = argv[2];
    if (argc > 3) regs.rcx = argv[3];
    if (argc > 4) regs.r8  = argv[4];
    if (argc > 5) regs.r9  = argv[5];

    if (argc > 6) {
        int stack_args = argc - 6;
        uintptr_t stack_sp = sp - (stack_args * sizeof(uintptr_t));
        stack_sp &= ~0xF;
        write_remote_mem(pid, stack_sp, &argv[6], stack_args * sizeof(uintptr_t));
        sp = stack_sp;
    }

    regs.rsp = sp;
    regs.rip = func_addr;
    regs.rax = 0;

    if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) == -1) goto fail;
    if (ptrace(PTRACE_CONT, pid, NULL, NULL) == -1) goto fail;

    waitpid(pid, &status, WUNTRACED);

    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1) goto fail;
    uintptr_t ret_val = regs.rax;

    if (has_fp) {
        if (ptrace(PTRACE_GETFPREGS, pid, NULL, &fpregs) == 0) {
            if (is_fp) {
                memcpy(&ret_val, &fpregs.xmm_space[0], sizeof(uintptr_t));
            }
        }
        ptrace(PTRACE_SETFPREGS, pid, NULL, &orig_fpregs);
    }

    ptrace(PTRACE_SETREGS, pid, NULL, &orig_regs);
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    return ret_val;

#elif defined(__arm__)
    struct local_pt_regs regs, orig_regs;
    struct local_user_vfp vfp, orig_vfp;
    struct iovec iov = { &regs, sizeof(regs) };
    struct iovec orig_iov = { &orig_regs, sizeof(orig_regs) };
    struct iovec fp_iov = { &vfp, sizeof(vfp) };
    struct iovec orig_fp_iov = { &orig_vfp, sizeof(orig_vfp) };

    if (ptrace(PTRACE_GETREGSET, pid, (void *)NT_PRSTATUS, &iov) == -1) goto fail;
    memcpy(&orig_regs, &regs, sizeof(regs));

    int has_fp = (ptrace(PTRACE_GETREGSET, pid, (void *)NT_ARM_VFP, &fp_iov) == 0);
    if (has_fp) {
        memcpy(&orig_vfp, &vfp, sizeof(vfp));
        for (int i = 0; i < argc && i < 8; ++i) {
            vfp.fpregs[i] = argv[i];
        }
        fp_iov.iov_len = sizeof(vfp);
        ptrace(PTRACE_SETREGSET, pid, (void *)NT_ARM_VFP, &fp_iov);
    }

    uintptr_t sp = regs.ARM_sp;
    sp = (sp - 1024) & ~0x7;

    for (int i = 0; i < argc && i < 4; ++i) {
        regs.uregs[i] = argv[i];
    }
    if (argc > 4) {
        int stack_args = argc - 4;
        sp -= stack_args * sizeof(uintptr_t);
        sp &= ~0x7;
        write_remote_mem(pid, sp, &argv[4], stack_args * sizeof(uintptr_t));
    }

    regs.ARM_sp = sp;
    regs.ARM_lr = 0;
    regs.ARM_pc = func_addr;

    if (ptrace(PTRACE_SETREGSET, pid, (void *)NT_PRSTATUS, &iov) == -1) goto fail;
    if (ptrace(PTRACE_CONT, pid, NULL, NULL) == -1) goto fail;

    waitpid(pid, &status, WUNTRACED);

    if (ptrace(PTRACE_GETREGSET, pid, (void *)NT_PRSTATUS, &iov) == -1) goto fail;
    uintptr_t ret_val = regs.ARM_r0;

    if (has_fp) {
        fp_iov.iov_len = sizeof(vfp);
        if (ptrace(PTRACE_GETREGSET, pid, (void *)NT_ARM_VFP, &fp_iov) == 0) {
            if (is_fp) {
                ret_val = (uintptr_t)vfp.fpregs[0];
            }
        }
        orig_fp_iov.iov_len = sizeof(orig_vfp);
        ptrace(PTRACE_SETREGSET, pid, (void *)NT_ARM_VFP, &orig_fp_iov);
    }

    ptrace(PTRACE_SETREGSET, pid, (void *)NT_PRSTATUS, &orig_iov);
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    return ret_val;

#elif defined(__i386__)
    struct local_user_regs_struct_32 regs, orig_regs;
    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1) goto fail;
    memcpy(&orig_regs, &regs, sizeof(regs));

    uintptr_t sp = regs.esp;
    sp = (sp - 1024) & ~0xF;

    uintptr_t dummy_ret = 0;
    size_t total_stack = (argc + 1) * sizeof(uintptr_t);
    sp -= total_stack;
    sp &= ~0xF;

    write_remote_mem(pid, sp, &dummy_ret, sizeof(uintptr_t));
    if (argc > 0) {
        write_remote_mem(pid, sp + sizeof(uintptr_t), argv, argc * sizeof(uintptr_t));
    }

    regs.esp = sp;
    regs.eip = func_addr;

    if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) == -1) goto fail;
    if (ptrace(PTRACE_CONT, pid, NULL, NULL) == -1) goto fail;

    waitpid(pid, &status, WUNTRACED);

    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1) goto fail;
    uintptr_t ret_val = regs.eax;

    ptrace(PTRACE_SETREGS, pid, NULL, &orig_regs);
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    return ret_val;

#else
#error "Unsupported Target Architecture"
#endif

fail:
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    return (uintptr_t)-1;
}

#endif
