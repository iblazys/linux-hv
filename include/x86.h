#ifndef _LINUXHV_X86_H
#define _LINUXHV_X86_H

// Linux below, windows later
// -----------------------------------------

#include <linux/kernel.h> /* Needed for pr_info() */
#include <linux/slab.h> // kalloc / kzalloc
#include <linux/gfp.h> // GFP_FLAGS

#include <asm/msr.h> // rdmsrl
#include <asm/errno.h> // asm error numbers (-EAGAIN etc)
#include <asm/special_insns.h>

#include "cpuid.h" // careful of redefinitions

static inline unsigned long __readcr0(void)
{
	return read_cr0(); // in special_insns.h
}

static inline void __writecr0(unsigned long value)
{
	write_cr0(value);
}


static inline unsigned long long __readmsr(u32 msr)
{
	unsigned long long x;
	rdmsrl(msr, x);
	return x;
}

static inline void __writemsr(u32 msr, u64 val)
{
	wrmsr(msr, (u32)val, (u32)(val >> 32));
}

static inline uint64_t __readcr4(void)
{
    uint64_t cr4;
    __asm("mov %%cr4, %0" : "=r" (cr4));
    return cr4;
}

static inline void __writecr4(uint64_t cr4)
{
	__asm("mov %0, %%cr4" :: "r"(cr4));
}

static inline int __vmx_on(void* phys)
{
	uint8_t ret;

	__asm__ __volatile__ (
        "vmxon %[pa]; setna %[ret]"
		: [ret]"=rm"(ret)
		: [pa]"m"(phys)
		: "cc", "memory");

	return ret;
}

#endif