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

enum Query
{
    MODE = 1,
    PAGE_SIZE,
}
