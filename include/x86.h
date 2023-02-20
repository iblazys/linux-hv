#ifndef _LINUXHV_X86_H
#define _LINUXHV_X86_H

#include "ia32.h"

#ifndef __linux__
// windows later
#include <ntddk.h>
#else

#define __readdr(dr) __extension__ ({			\
	unsigned long long val;				\
	__asm __volatile("movq %%dr" #dr ", %0"		\
			 : "=r" (val));			\
	val;						\
})

//
// Instead of searching through the mess of linux headers
// for the required intrinsics, they are all here for simplicity
// 
#define __align(alignment)	__attribute__((__aligned__(alignment)))

#include <linux/kernel.h> /* Needed for pr_info() */
#include <linux/slab.h> // kalloc / kzalloc
#include <linux/gfp.h> // GFP_FLAGS

#include <asm/msr.h> // rdmsrl
#include <asm/errno.h> // asm error numbers (-EAGAIN etc)
#include <asm/special_insns.h>
#include <asm/page.h>

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

static inline uint64_t __readcr3(void)
{
    uint64_t ret;

    __asm__ __volatile__(
        "mov %%cr3, %0"
        : "=r"(ret)
        : : "memory"
        );

    return ret;
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

static inline uint64_t __readrflags(void)
{
    u64 rflags;
	__asm __volatile("pushfq\n\tpopq %0" : "=r" (rflags));
	return rflags;
}

// ---------------- VMX -------------------
// move these to vmx.c ?

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

static inline uint8_t __vmx_off(void)
{
	uint8_t cf = 0;
    uint8_t zf = 0;
    /* Takes the logical processor out of VMX operation. If VMXON failed with an
     * invalid VMCS, CF is set. Otherwise, ZF is set and the error field in the
     * VMCS is set. */
    asm volatile(
        "vmxoff\n"
        "setb %[cf]\n"
        "setz %[zf]\n"
        : [ cf ] "=rm"(cf), [ zf ] "=rm"(zf)::"cc", "memory");

    if (zf) {
		pr_info("VMXOFF failed with error: ");
        // todo: vmread error
        return 1;
    }

    return cf | zf;
}

static inline uint8_t __vmx_vmclear(void* vmcs_phys_addr)
{
    uint8_t ret;

    asm volatile(
        "vmclear %[vmcs_region_ptr]\n"
        "setb %[ret]\n"
        : [ ret ] "=rm"(ret)
        : [ vmcs_region_ptr ] "m"(vmcs_phys_addr)
        : "cc", "memory");

    return ret;
}

static inline uint8_t __vmx_vmptrld(void* vmcs_phys_addr)
{
    uint8_t ret;

    asm volatile(
        "vmptrld %[vmcs_region_ptr]\n"
        "setb %[ret]\n"
        : [ ret ] "=rm"(ret)
        : [ vmcs_region_ptr ] "m"(vmcs_phys_addr)
        : "cc", "memory");

    return ret;
}

static inline uint8_t __vmx_vmcall(uintptr_t hc, void *d)
{
	uint8_t error;
	__asm __volatile("vmcall; setna %0"
			 : "=q" (error)
			 : "c" (hc), "d" (d)
			 : "cc");
	return error;
}

// testing
static inline uint64_t vmread(uint64_t field) {
    uint64_t value;
    asm volatile("vmread %[field], %[value]\n"
                 : [ value ] "=r"(value)
                 : [ field ] "r"(field)
                 : "cc", "memory");
    return value;
}
// testing

static inline uint8_t __vmx_vmread(size_t field, size_t* value)
{
	uint8_t error;

	__asm __volatile("vmread %2, %0; setna %1"
			 : "=r" (*value), "=qm" (error)
			 : "r" (field)
			 : "cc");
             
	return error;
}

static inline uint8_t __vmx_vmwrite(uint64_t field, uint64_t value)
{
    uint8_t ret;

    asm volatile(
        "vmwrite %[value], %[field]\n"
        "setb %[ret]\n"
        : [ ret ] "=rm"(ret)
        : [ value ] "r"(value), [ field ] "rm"(field)
        : "cc", "memory");

    return ret;
}

static inline uint8_t __vmx_vmlaunch(void)
{
	uint8_t error;
	__asm __volatile("vmlaunch; setna %0"
			 : "=q" (error)
			 : /* no reads  */
			 : "cc");
	return error;
}

// ----------------------- SELECTORS -----------------------

static inline uint16_t __readcs(void)
{
    u16 tmp;
    __asm __volatile("movw %%cs, %0" : "=r" (tmp));
    return tmp;
}

static inline uint16_t __readds(void)
{
    u16 tmp;
    __asm __volatile("movw %%ds, %0" : "=r" (tmp));
    return tmp;
}

static inline uint16_t __reades(void)
{
    u16 tmp;
    __asm __volatile("movw %%es, %0" : "=r" (tmp));
    return tmp;
}

static inline uint16_t __readfs(void)
{
    u16 tmp;
    __asm __volatile("movw %%fs, %0" : "=r" (tmp));
    return tmp;
}

static inline uint16_t __readgs(void)
{
    u16 tmp;
    __asm __volatile("movw %%gs, %0" : "=r" (tmp));
    return tmp;
}

static inline uint16_t __readss(void)
{
    u16 tmp;
    __asm __volatile("movw %%ss, %0" : "=r" (tmp));
    return tmp;
}

static inline uint16_t __readldtr(void)
{
    u16 tmp;
    __asm __volatile("sldt %0" : "=r" (tmp));
    return tmp;
}

static inline uint16_t __readtr(void)
{
    u16 tmp;
    __asm __volatile("str %0" : "=r" (tmp));
    return tmp;
}

static inline uint32_t __segmentlimit(uint32_t selector)
{
	uint32_t limit;
	__asm __volatile("lsl %1, %0" : "=r" (limit) : "r" (selector));
	return limit;
}

static inline void __sgdt(segment_descriptor_register_64* gdt)
{
    __asm __volatile("sgdt %0" : "=m" (*gdt));
}

static inline void __sidt(segment_descriptor_register_64* idt)
{
    __asm__ __volatile("sidt %0" : "=m" (*idt));
}

static inline uint64_t __loadar(uint64_t sel)
{
	uint64_t ar;
	__asm __volatile("lar %1, %0"
			 : "=r" (ar)
			 : "r" (sel));
	return ar;
}

// testing
static inline uint32_t __accessright(uint16_t selector)
{
	if (selector)
		return (__loadar(selector) >> 8) & 0xF0FF;

	/* unusable  */
	return 0x10000;
}


static inline uint64_t get_canonical(uint64_t la)
{
	return ((int64_t)la << 16) >> 16;
}


#endif // __linux__
#endif // _LINUXHV_X86_H