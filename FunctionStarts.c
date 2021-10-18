//
//  FunctionStarts.c
//  FunctionStarts
//
//  Created by Nick Dowell on 15/10/2021.
//

#include <assert.h>
#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <stdio.h>
#include <string.h>

void dump_function_starts(void) {
    const uint32_t image_count = _dyld_image_count();
    for (uint32_t image_index = 0; image_index < image_count; image_index++) {
        const struct mach_header_64 *header = (const void *)_dyld_get_image_header(image_index);
        
        printf("0x%0llX [%3d] %s 0x%0lX%s\n", (uint64_t)header, image_index,
               _dyld_get_image_name(image_index),
               _dyld_get_image_vmaddr_slide(image_index),
               header->flags & MH_DYLIB_IN_CACHE ? " [DyldSharedCache]" : "");
        
        intptr_t slide = _dyld_get_image_vmaddr_slide(image_index);
        
        uint64_t linkedit_seg_start = 0;
        uint64_t linkedit_seg_end = 0;
        uint64_t linkedit_seg_fileoff = 0;
        
        uint64_t text_seg_start = 0;
        uint64_t text_sect_start = 0;
        uint64_t text_sect_end = 0;
        
        const struct load_command *load_cmd = (const void *)(header + 1);
        for (uint32_t i = 0; i < header->ncmds; ++i) {
            switch (load_cmd->cmd) {
                case LC_SEGMENT_64: {
                    const struct segment_command_64 *seg_cmd = (const void *)load_cmd;
                    
                    // The __LINKEDIT info is needed to compute the address of the Function Starts data
                    if (strncmp(seg_cmd->segname, SEG_LINKEDIT, sizeof(seg_cmd->segname)) == 0) {
                        linkedit_seg_fileoff = seg_cmd->fileoff;
                        linkedit_seg_start = seg_cmd->vmaddr + slide;
                        linkedit_seg_end = linkedit_seg_start + seg_cmd->vmsize;
                    }
                    
                    if (strncmp(seg_cmd->segname, SEG_TEXT, sizeof(seg_cmd->segname)) == 0) {
                        text_seg_start = seg_cmd->vmaddr + slide;
                        // Get the __text section info so that we can verify the function addresses parsed later
                        for (uint32_t sect_idx = 0; sect_idx < seg_cmd->nsects; sect_idx++) {
                            const struct section_64 *section = (const struct section_64 *)(seg_cmd + 1) + sect_idx;
                            if (strncmp(section->sectname, SECT_TEXT, sizeof(section->sectname)) == 0) {
                                text_sect_start = section->addr + slide;
                                text_sect_end = text_sect_start + section->size;
                                break;
                            }
                        }
                    }
                    
                    break;
                }
                case LC_FUNCTION_STARTS: {
                    const struct linkedit_data_command *data_cmd = (const void *)load_cmd;
                    assert(data_cmd->dataoff > linkedit_seg_fileoff);
                    const uint32_t offset_from_linkedit = data_cmd->dataoff - linkedit_seg_fileoff;
                    const uint8_t *start = (const uint8_t *)linkedit_seg_start + offset_from_linkedit;
                    const uint8_t *end = start + data_cmd->datasize;
                    assert((uintptr_t)end < linkedit_seg_end);
                    
                    uint64_t address = text_seg_start;
                    // Function starts are stored as a series of offsets encoded as LEB128.
                    // Adapted from DyldInfoPrinter<A>::printFunctionStartsInfo() in ld64-127.2/src/other/dyldinfo.cpp
                    for (const uint8_t *p = start; (*p != 0) && (p < end); ) {
                        uint64_t delta = 0;
                        uint32_t shift = 0;
                        bool more = true;
                        do {
                            uint8_t byte = *p++;
                            delta |= ((byte & 0x7F) << shift);
                            shift += 7;
                            if (byte < 0x80) {
                                address += delta;
                                assert(// Function address resides in the __text section
                                       address >= text_sect_start && address < text_sect_end);
                                
                                Dl_info dlinfo = {0};
                                if (dladdr((void *)address, &dlinfo) && (uint64_t)dlinfo.dli_saddr == address) {
                                    printf("0x%0llX   %s\n", address, dlinfo.dli_sname);
                                } else {
                                    printf("0x%0llX\n", address);
                                }
                                more = false;
                            }
                        } while (more);
                    }
                    break;
                }
            }
            load_cmd = (const void *)((const char *)load_cmd) + load_cmd->cmdsize;
        }
        printf("\n");
    }
}

int main(int argc, const char * argv[]) {
    dump_function_starts();
    return 0;
}
