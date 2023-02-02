#include <linux/kernel.h> /* Needed for pr_info() */ 
#include "vmm.h"

#include "../include/ia32-doc/out/ia32.h" // will need this in almost every file

bool InitVMM(void)
{
    if(!IsVMXSupported()) 
    {
        pr_info("Your processor does not support vmx");
        return false;
    }
    
    return true;
}

bool IsVMXSupported(void)
{

    return false;
}