#ifndef __LINUXHV_VMXASM_H
#define __LINUXHV_VMXASM_H

extern int __vmx_vminit(struct vmm_state*);
extern void __vmx_entrypoint(void);

#endif