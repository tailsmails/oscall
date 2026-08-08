#include <setjmp.h>
#include <signal.h>

static sigjmp_buf g_jmp_env;
static void v_segfault_handler(int sig) { siglongjmp(g_jmp_env, 1); }
static int safe_sigsetjmp() { return sigsetjmp(g_jmp_env, 1); }
