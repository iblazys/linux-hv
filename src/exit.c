#include "exit.h"
#include "vmm.h"
#include "asmdefs.h"

uint8_t ExitVmExitHandler(VIRTUAL_CPU* test, GUEST_REGISTERS* exit_state)
{
    pr_err("VMEXIT");
    return 0;
}
