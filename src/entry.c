/* 
 * entry.c - The entry point of our hypervisor. 
 */ 

#include <linux/kernel.h> /* Needed for pr_info() */ 
#include <linux/module.h> /* Needed by all modules */

#include "vmm.h"

static struct vmm_state* vmm_state;

int init_module(void) 
{ 
    pr_info("linux-hv: hypervisor loading.\n"); 

    vmm_state = vmm_init();

    if(!vmm_state)
    {
        pr_err("linux-hv: hypervisor failed to load");
        return 0;
    }

    pr_info("linux-hv: hypervisor loaded.\n");


    // DEBUG 
    //pr_info("shutting down hypervisor");
   
    //pr_info("hypervisor shutdown successfully");
    // DEBUG


    /* A non 0 return means init_module failed; module can't be loaded. */
    return 0; 
} 

void cleanup_module(void) 
{ 
    pr_info("hypervisor unloading.\n");

    vmm_shutdown(vmm_state);

    pr_info("hypervisor unloaded.\n");
} 

MODULE_LICENSE("GPL");