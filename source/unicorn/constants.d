module unicorn.constants;

enum Arch
{
    ARM = 1,
    ARM64,
    MIPS,
    X86,
    PPC,
    SPARC,
    M68K,
}

enum Mode
{
    LITTLE_ENDIAN = 0,
    MODE_16 = 1 << 1,
    MODE_32 = 1 << 2,
    MODE_64 = 1 << 3,
    THUMB = 1 << 4,
    MCLASS = 1 << 5,
    V8 = 1 << 6,
    BIG_ENDIAN = 1 << 30,
}

enum Status
{
    OK = 0, // No error: everything was fine
    NOMEM, // Out-Of-Memory error: uc_open(), uc_emulate()
    ARCH, // Unsupported architecture: uc_open()
    HANDLE, // Invalid handle
    MODE, // Invalid/unsupported mode: uc_open()
    VERSION, // Unsupported version (bindings)
    READ_UNMAPPED, // Quit emulation due to READ on unmapped memory: uc_emu_start()
    WRITE_UNMAPPED, // Quit emulation due to WRITE on unmapped memory: uc_emu_start()
    ETCH_UNMAPPED, // Quit emulation due to FETCH on unmapped memory: uc_emu_start()
    HOOK, // Invalid hook type: uc_hook_add()
    INSN_INVALID, // Quit emulation due to invalid instruction: uc_emu_start()
    MAP, // Invalid memory mapping: uc_mem_map()
    WRITE_PROT, // Quit emulation due to UC_MEM_WRITE_PROT violation: uc_emu_start()
    READ_PROT, // Quit emulation due to UC_MEM_READ_PROT violation: uc_emu_start()
    FETCH_PROT, // Quit emulation due to UC_MEM_FETCH_PROT violation: uc_emu_start()
    ARG, // Inavalid argument provided to uc_xxx function (See specific function API)
    READ_UNALIGNED, // Unaligned read
    WRITE_UNALIGNED, // Unaligned write
    FETCH_UNALIGNED, // Unaligned fetch
    HOOK_EXIST, // hook for this event already existed
}

enum Protection : uint
{
    PROT_NONE = 0,
    PROT_READ = 1,
    PROT_WRITE = 2,
    PROT_EXEC = 4,
    PROT_ALL = 7,
}

extern(C) struct MemRegion
{
    ulong begin;
    ulong end;
    Protection perms;
}

enum MemType
{
    READ = 16, // Memory is read from
    WRITE, // Memory is written to
    FETCH, // Memory is fetched
    READ_UNMAPPED, // Unmapped memory is read from
    WRITE_UNMAPPED, // Unmapped memory is written to
    MEM_FETCH_UNMAPPED, // Unmapped memory is fetched
    WRITE_PROT, // Write to write protected, but mapped, memory
    READ_PROT, // Read from read protected, but mapped, memory
    FETCH_PROT, // Fetch from non-executable, but mapped, memory
}

enum HookType
{
    INTR = 1 << 0, // Hook all interrupt/syscall events
    INSN = 1 << 1, // Hook a particular instruction
    CODE = 1 << 2, // Hook a range of code
    BLOCK = 1 << 3, // Hook basic blocks
    MEM_READ_UNMAPPED = 1 << 4, // Hook for memory read on unmapped memory
    MEM_WRITE_UNMAPPED = 1 << 5, // Hook for invalid memory write events
    MEM_FETCH_UNMAPPED = 1 << 6, // Hook for invalid memory fetch for execution events
    MEM_READ_PROT = 1 << 7, // Hook for memory read on read-protected memory
    MEM_WRITE_PROT = 1 << 8, // Hook for memory write on write-protected memory
    MEM_FETCH_PROT = 1 << 9, // Hook for memory fetch on non-executable memory
    MEM_READ = 1 << 10, // Hook memory read events.
    MEM_WRITE = 1 << 11, // Hook memory write events.
    MEM_FETCH = 1 << 12, // Hook memory fetch for execution events
}

enum CodeHookType
{
    CODE = 1 << 2, // Hook a range of code
    BLOCK = 1 << 3, // Hook basic blocks
}

enum MemHookType
{
    MEM_READ_UNMAPPED = 1 << 4, // Hook for memory read on unmapped memory
    MEM_WRITE_UNMAPPED = 1 << 5, // Hook for invalid memory write events
    MEM_FETCH_UNMAPPED = 1 << 6, // Hook for invalid memory fetch for execution events
    MEM_READ_PROT = 1 << 7, // Hook for memory read on read-protected memory
    MEM_WRITE_PROT = 1 << 8, // Hook for memory write on write-protected memory
    MEM_FETCH_PROT = 1 << 9, // Hook for memory fetch on non-executable memory
    MEM_READ = 1 << 10, // Hook memory read events.
    MEM_WRITE = 1 << 11, // Hook memory write events.
    MEM_FETCH = 1 << 12, // Hook memory fetch for execution events
    MEM_UNMAPPED = 0b111 << 4, // hook type for all events of unmapped memory access
    MEM_PROT = 0b111 << 7, // hook type for all events of illegal protected memory access
    MEM_READ_INVALID = (1 << 4) | (1 << 7), /* Hook type for all events of illegal read memory access */
    MEM_WRITE_INVALID = (1 << 5) | (1 << 8), /* Hook type for all events of illegal write memory access/ */
    MEM_FETCH_INVALID = (1 << 6) | (1 << 9), /* Hook type for all events of illegal fetch memory access */
    MEM_INVALID = (0b111111 << 4), // Hook type for all events of illegal memory access
    MEM_VALID = (0b111 << 10), // Hook type for all events of valid memory access
    MEM_ALL = 0b111111111 << 4, // Hook type for all events.
}

enum Query
{
    MODE = 1,
    PAGE_SIZE,
}
