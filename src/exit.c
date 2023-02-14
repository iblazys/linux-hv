#include "exit.h"

bool exit_handle_vmexit(uintptr_t *stack)
{
     pr_info("VMEXIT HANDLER");

     return true;
}

void exit_handle_fail(uintptr_t *stack)
{
    pr_info("exit failed");
}