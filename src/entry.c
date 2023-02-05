/* 
 * entry.c - The entry point of our hypervisor. 
 */ 

#include <linux/kernel.h> /* Needed for pr_info() */ 
#include <linux/module.h> /* Needed by all modules */

#include "vmm.h"

static VMM_STATE* VmmState;

int init_module(void) 
{ 
    pr_info("hypervisor loading.\n"); 
    VmmState = VmmInit();

    if(VmmState == -1)
    {
        pr_info("hypervisor failed to load");
        return 0;
    }

    /* A non 0 return means init_module failed; module can't be loaded. */ 
    pr_info("hypervisor loaded.\n");

    return 0; 
} 

void cleanup_module(void) 
{ 
    pr_info("hypervisor unloading.\n");

    // make vmm state available here without globals preferably
    on_each_cpu((void*)VmmShutdown, VmmState, true);

    // Free VMM_STATE and GUEST_CPU states - only call this once
    VmmDestroy(VmmState);

    pr_info("hypervisor unloaded.\n");
} 

MODULE_LICENSE("GPL");