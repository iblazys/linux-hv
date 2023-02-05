#ifndef LINUXHV_EXIT_H
#define LINUXHV_EXIT_H

#include <linux/types.h>
#include "vmm.h"
#include "asmdefs.h"

uint8_t ExitVmExitHandler(VIRTUAL_CPU* test, GUEST_REGISTERS* exit_state);

#endif