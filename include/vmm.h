#ifndef MYLINUXHV_VMM_H
#define MYLINUXHV_VMM_H

#include "x86.h"

#define __PAGE_SIZE 4096

struct virtual_cpu
{
    // The id of the current processor
    uint32_t    processor_id;

    // Has memory been allocated
    bool        is_loaded;

    // Did the launch fail
    bool        launch_failed;

    uint64_t    vmxon_region_phys; // 32 bit
    uint64_t    vmxon_region_virt;
    uint64_t    vmcs_region_phys;
    uint64_t    vmcs_region_virt;

    struct cpu_saved_state* saved_state;
    struct vmm_state*   vmm;
};

struct cpu_saved_state
{
    segment_descriptor_register_64 gdtr;
    segment_descriptor_register_64 idtr;
};

struct vmm_state
{
    bool init_status;
    uint32_t number_of_cpus;
    struct virtual_cpu* guest_cpus;

    // controls
    // capabilites
};

struct vmm_state* vmm_init(void);
struct vmm_state* vmm_allocate_vmm_state(void);
struct virtual_cpu* vmm_allocate_virtual_cpus(uint32_t num_of_cpus);
int vmm_allocate_saved_state(struct virtual_cpu* vcpu);

void vmm_virtualize_single_cpu(void* info);

void vmm_free_vmm_state(struct vmm_state* vmm);
void vmm_free_virtual_cpus(struct vmm_state* vmm);

void vmm_shutdown_cpu(struct vmm_state* vmm);
void vmm_shutdown(struct vmm_state* vmm);

#endif