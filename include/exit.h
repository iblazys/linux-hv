#ifndef __LINUXHV_EXIT_H
#define __LINUXHV_EXIT_H

#include "x86.h"

bool exit_handle_vmexit(uintptr_t *stack);
void exit_handle_fail(uintptr_t *stack);

#endif