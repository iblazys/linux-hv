#ifndef LINUXHV_ASMDEFS_H
#define LINUXHV_ASMDEFS_H

#ifndef __linux__
#include <ntddk.h> // for future windows integration
#else

#include <asm/msr.h>
#include <cpuid.h>

extern void InitSingleCpuEntry(void*); // asmdefs.S
extern void* EntryToVmExit; // asmdefs.S

struct _GUEST_REGISTERS 
{
    // TODO: invert the order
    
    u64 r15;
    u64 r14;
    u64 r13;
    u64 r12;
    u64 r11;
    u64 r10;
    u64 r9;
    u64 r8;
    u64 rdi;
    u64 rsi;
    u64 rdx;
    u64 rcx;
    u64 rbx;
    u64 rax;
    /* RSP must be read from the VMCS within the vmexit handler. */
    u64 _padding;
    u64 rbp;
} __attribute__((aligned(16)));

typedef struct _GUEST_REGISTERS GUEST_REGISTERS;

static inline int __vmx_on(uint64_t phys)
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
        : [ cf ] "=rm"(cf), [ zf ] "=rm"(zf)::"cc", "memory"
    );

    if (zf) 
    { 
        pr_err("VMXOFF failed"); // todo: read error
        return 1;
    }

    return cf | zf;
}

static inline uint8_t __vmx_vmclear(void* vmcsRegionPtr)
{
    uint8_t ret;

    asm volatile(
        "vmclear %[vmcsRegionPtr]\n"
        "setb %[ret]\n"
        : [ ret ] "=rm"(ret)
        : [ vmcsRegionPtr ] "m"(vmcsRegionPtr)
        : "cc", "memory");

	return ret;
}

static inline uint8_t __vmx_vmptrld(void* vmcsRegionPtr)
{
    uint8_t ret;

    __asm__ __volatile__(
        "vmptrld %[vmcsRegionPtr]\n"
        "setb %[ret]\n"
        : [ ret ] "=rm"(ret)
        : [ vmcsRegionPtr ] "m"(vmcsRegionPtr)
        : "cc", "memory"
    );
        
    return ret;
}

static inline uint8_t __vmx_vmlaunch(void)
{
    u8 err;

    asm volatile(
        "vmlaunch\n"
        "setb %[err]\n"
        : [ err ] "=rm"(err)::"cc", "memory"
    );

    return err;
}

static inline uint8_t __vmx_vmwrite(unsigned long field, unsigned long value) 
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

static inline uint64_t __readcr0(void)
{
    uint64_t ret;

    __asm__ __volatile__(
        "mov %%cr0, %0"
        : "=r"(ret)
        : : "memory"
        );

    return ret;
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

static inline void _writecr0(uint64_t cr0)
{
    __asm__ __volatile__(
        "mov %0, %%cr0"
        : : "r"(cr0)
        : "memory"
        );
}

static inline uint64_t __readcr4(void)
{
    uint64_t ret;

    __asm__ __volatile__(
        "mov %%cr4, %0" // 0 refers to the first item in the constraints
        : "=r"(ret) // indicates result is held in memory
        : : "memory"
    );
    
    return ret;
}

static inline void _writecr4(uint64_t cr4)
{
    __asm__ __volatile__(
        "mov %0, %%cr4"
        : : "r"(cr4) 
        : "memory"
        );
}

static inline uint64_t __readmsr(unsigned long __register)
{
  unsigned long __edx;
  unsigned long __eax;

  __asm__ ("rdmsr" : "=d"(__edx), "=a"(__eax) : "c"(__register));

  return (((uint64_t)__edx) << 32) | (uint64_t)__eax;
}

static inline void _writemsr(unsigned long __register, unsigned long value)
{
      unsigned int low = value & 0xFFFFFFFF;
      unsigned int high = value >> 32;

      __wrmsr(__register, low, high);
}

static inline uint64_t __load_ar(uint16_t selector)
{
    uint64_t ret;

	__asm__ __volatile__(
        "lar %1, %0"
        : "=r" (ret)
        : "r" (selector));

    return ret;
}

static inline uint16_t _getcs(void)   
{   
    uint16_t ret;    
    __asm__ __volatile("movw %%cs, %0" : "=r" (ret));   
    return ret;
}

static inline uint16_t _getds(void)   
{   
    uint16_t ret;    
    __asm__ __volatile("movw %%ds, %0" : "=r" (ret));   
    return ret;
}

static inline uint16_t _getes(void)   
{   
    uint16_t ret;    
    __asm__ __volatile("movw %%es, %0" : "=r" (ret));   
    return ret;
}

static inline uint16_t _getfs(void)   
{   
    uint16_t ret;    
    __asm__ __volatile("movw %%fs, %0" : "=r" (ret));   
    return ret;
}

static inline uint16_t _getgs(void)   
{   
    uint16_t ret;    
    __asm__ __volatile("movw %%gs, %0" : "=r" (ret));   
    return ret;
}

static inline uint16_t _getss(void)   
{   
    uint16_t ret;    
    __asm__ __volatile("movw %%ss, %0" : "=r" (ret));   
    return ret;
}

static inline uint16_t _getldtr(void)   
{   
    uint16_t ret;    
    __asm__ __volatile("sldt %0" : "=r" (ret));   
    return ret;
}

static inline uint16_t _gettr(void)   
{   
    uint16_t ret;    
    __asm__ __volatile("str %0" : "=r" (ret));   
    return ret;
}

static inline unsigned long __segmentlimit(const unsigned long segreg) 
{
  unsigned long retval;

  __asm__ __volatile__(
        "lsl %[segreg], %[retval]"
        : [retval] "=r"(retval)
        : [segreg] "rm"(segreg)
        );
        
  return retval;
}

static inline void _sgdt(void* gdt)
{
    __asm__ __volatile("sgdt %0":"=m" (*gdt));
}

static inline void _sidt(void* idt)
{
    __asm__ __volatile("sidt %0" : "=m" (*idt));
}

#endif // __linux__
#endif // LINUXHV_ASMDEFS_H