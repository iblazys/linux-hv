/* 
 * entry.c - The entry point of our hypervisor. 
 */ 

#include <linux/kernel.h> /* Needed for pr_info() */ 
#include <linux/module.h> /* Needed by all modules */

#include "vmm.h"

static struct vmm_state* vmm_state;

int init_module(void) 
{ 
    pr_info("hypervisor loading.\n"); 

    vmm_state = vmm_init();

    if(!vmm_state)
    {
        pr_err("hypervisor failed to load");
    }

    pr_info("hypervisor loaded.\n");


    // DEBUG 
    pr_info("shutting down hypervisor");
    vmm_shutdown(vmm_state);
   
    pr_info("hypervisor shutdown successfully");
    // DEBUG


    /* A non 0 return means init_module failed; module can't be loaded. */
    return 0; 
} 

void cleanup_module(void) 
{ 
    pr_info("hypervisor unloading.\n");
    
    // Temporary for developing, run shutdown on all cpu's
    //on_each_cpu((void*)vmm_shutdown, VmmState, true);

    // Free VMM_STATE and GUEST_CPU states - only call this once
    //vmm_shutdown(vmm_state);

    pr_info("hypervisor unloaded.\n");
} 

MODULE_LICENSE("GPL");