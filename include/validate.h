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

#endif