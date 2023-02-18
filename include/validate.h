#ifndef __LINUXHV_VALIDATE_H
#define __LINUXHV_VALIDATE_H

#include "x86.h"

#ifndef ASSERT
#define ASSERT(condition) do { if (!(condition)) BUG(); } while(0)
#endif

#define MV_IS_FLAG_SET(F, SF)       ((bool)(((F) & (SF)) != 0))

typedef enum _segment_type
{
    SegmentCs,
    SegmentSs,
    SegmentDs,
    SegmentEs,
    SegmentFs,
    SegmentGs,
    SegmentTr,
    SegmentLdtr
} segment_type;

void validate_guest_entry_state(void);

cr0 validate_adjust_cr0(cr0 _cr0);
cr0 validate_adjust_guest_cr0(cr0 _cr0);

cr4 validate_adjust_cr4(cr4 _cr4);
cr4 validate_adjust_guest_cr4(cr4 _cr4);

void validate_segment_access_rights(segment_type segment_type,
    uint32_t access_rights_as_uint32,
    uint32_t segment_limit,
    uint16_t segment_selector_as_uint16,
    bool ia32e_mode_guest,
    bool unrestricted_guest);

/*
* Checks if the high bits of the supplied address 
* are either all zeros or all ones and returns the result
*/
static inline void validate_is_canonical_address(void *addr, const char* file, int line) 
{
  uint64_t addr_value = (uint64_t)addr;
  uint16_t high_bits = (uint16_t)(addr_value >> 48);

  if(!(high_bits == 0 || high_bits == 0xffff))
  {
    pr_err("%s:%d address 0x%llx is not canonical", file, line, addr_value);
    ASSERT(false);
  }

  //return (high_bits == 0 || high_bits == 0xffff);
}

static inline void validate_is_bit_set(unsigned int num, int pos) {
    // Create a mask with a 1 in the bit position we want to check
    unsigned int mask = 1 << pos;

    // Check if the bit is set by performing a bitwise AND with the mask
    // If the result is non-zero, the bit is set
    //return (num & mask) != 0;

    if((num & mask) == 0)
    {
      ASSERT(false);
    }
}

#endif