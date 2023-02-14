# linux-hv
super simple intel based linux hypervisor

this is by no means stable and is purely for learning purposes.

written and tested with WSL2 v1.0.3.0 on kernel version **5.15.83.1-microsoft-standard-WSL2+**

you have to compile your own (at the time of writing) because the included kernel does not have all the headers.

you can find the official kernel source [here](https://github.com/microsoft/WSL2-Linux-Kernel)

basic control flow of the hypervisor is:

    vmm_init (vmm.c)
        on_each_cpu(__vmx_vminit) (vmx_asm.S):
                vmm_virtualize_single_cpu (vmm.c):
                        VMLAUNCH -> exit_handle_vmexit (exit.c)


## Acknowledgements

 - [ia32-doc](https://github.com/ia32-doc/ia32-doc)
 - [hypervisor from scratch series](https://rayanfam.com/topics/hypervisor-from-scratch-part-1/)
 - [ksm](https://github.com/asamy/ksm)


