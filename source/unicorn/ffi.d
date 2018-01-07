module unicorn.ffi;

import unicorn.constants;

extern (C):
nothrow:
@nogc:

alias uc_handle = size_t;
alias uc_hook = size_t;

uint uc_version(const uint* major, const uint* minor);
bool uc_arch_supported(Arch arch);
Status uc_open(Arch arch, Mode mode, uc_handle* engine);
Status uc_close(uc_handle engine);
Status uc_errno(uc_handle engine);
char* uc_strerror(Status error_code);
Status uc_reg_write(uc_handle engine, int regid, const void* value);
Status uc_reg_read(uc_handle engine, int regid, void* value);
Status uc_mem_write(uc_handle engine, ulong address, const ubyte* bytes,
                    size_t size);
Status uc_mem_read(uc_handle engine, ulong address, const ubyte* bytes,
                  size_t size);
Status uc_mem_map(uc_handle engine, ulong address, size_t size,
                  uint perms);
Status uc_mem_unmap(uc_handle engine, ulong address, size_t size);
Status uc_mem_protect(uc_handle engine, ulong address, size_t size,
                      uint perms);
Status uc_mem_regions(uc_handle engine, const MemRegion** regions,
                      uint* count);
Status uc_emu_start(uc_handle engine, ulong begin, ulong until,
                    ulong timeout, size_t count);
Status uc_emu_stop(uc_handle engine);
Status uc_query(uc_handle engine, Query query_type, size_t* result);
