#ifndef LINUXHV_CPU_H
#define LINUXHV_CPU_H

#include <stdbool.h>

bool cpu_supports_vmx(void);
void cpu_enable_vmx_operation(void);
void cpu_adjust_cr0_cr4_bits(void);

#endif