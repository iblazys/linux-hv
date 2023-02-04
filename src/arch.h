#ifndef LINUXHV_ARCH_H
#define LINUXHV_ARCH_H

#include <linux/kernel.h>

bool CpuHasVmxSupport(void);
bool CpuEnableVmxOperation(void);
bool CpuDisableVmxOperation(void);

#endif;