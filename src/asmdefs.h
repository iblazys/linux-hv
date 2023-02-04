#ifndef LINUXHV_ASMDEFS_H
#define LINUXHV_ASMDEFS_H

static inline int _vmxon(uint64_t phys)
{
	uint8_t ret;

	__asm__ __volatile__ (
        "vmxon %[pa]; setna %[ret]"
		: [ret]"=rm"(ret)
		: [pa]"m"(phys)
		: "cc", "memory");

	return ret;
}

static inline void _vmxoff(void)
{
    asm volatile (
        "vmxoff\n"
        : : : "cc"
        );
}

static inline uint64_t _readcr0(void)
{
    uint64_t ret;

    __asm__ __volatile__(
        "mov %%cr0, %0"
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

static inline uint64_t _readcr4(void)
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

static inline uint64_t _readmsr(unsigned long __register)
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

#endif