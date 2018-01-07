module unicorn.cpu;

import std.exception;
import std.format;
import std.string : fromStringz;
import std.typecons : tuple;

import unicorn.constants.common;
import unicorn.constants.x86;
import unicorn.ffi;

class UnicornError : Exception
{
    mixin basicExceptionCtors;
}

auto unicornVersion() nothrow @nogc
{
    uint major = 0;
    uint minor = 0;
    uc_version(&major, &minor);
    return tuple(major, minor);
}

bool archSupported(Arch arch) nothrow @nogc
{
    return uc_arch_supported(arch);
}

struct UnicornHook(F)
{
    Unicorn* unicorn;
    F callback;
}

alias CodeHook = UnicornHook!(void function(Unicorn*, ulong, uint));
alias IntrHook = UnicornHook!(void function(Unicorn*, uint));
alias MemHook = UnicornHook!(bool function(Unicorn*, MemType, ulong, size_t, long));
alias InsnInHook = UnicornHook!(uint function(Unicorn*, uint, size_t));
alias InsnOutHook = UnicornHook!(void function(Unicorn*, uint, size_t, uint));
alias InsnSysHook = UnicornHook!(void function(Unicorn*));

extern (C) void code_hook_proxy(uc_handle _, ulong address, uint size, CodeHook* user_data)
{
    (*user_data.callback)(user_data.unicorn, address, size);
}

extern (C) void intr_hook_proxy(uc_handle _, uint intno, IntrHook* user_data)
{
    (*user_data.callback)(user_data.unicorn, intno);
}

extern (C) bool mem_hook_proxy(uc_handle _, MemType memType, ulong address, size_t size,
                               long value, MemHook* user_data)
{
    return (*user_data.callback)(user_data.unicorn, memType, address, size, value);
}

extern (C) uint insn_in_hook_proxy(uc_handle _, uint port, size_t size, InsnInHook* user_data)
{
    return (*user_data.callback)(user_data.unicorn, port, size);
}

extern (C) void insn_out_hook_proxy(uc_handle _, uint port, size_t size, uint value,
                                    InsnOutHook* user_data)
{
    (*user_data.callback)(user_data.unicorn, port, size, value);
}

extern (C) void insn_sys_hook_proxy(uc_handle _, InsnSysHook* user_data)
{
    (*user_data.callback)(user_data.unicorn);
}

struct Unicorn
{
    uc_handle engine;

    this(Arch arch, Mode mode)
    {
        auto status = uc_open(arch, mode, &engine);
        if (status != Status.OK)
            throw new UnicornError(format("Error: %s", uc_strerror(status).fromStringz));
    }

    ~this()
    {
        uc_close(engine);
    }

    void regWrite(int regid, ulong value)
    {
        auto status = uc_reg_write(this.engine, regid, cast(const void*)&value);
        if (status != Status.OK)
            throw new UnicornError(format("Error: %s", uc_strerror(status).fromStringz));
    }

    ulong regRead(int regid)
    {
        ulong value;
        auto status = uc_reg_read(this.engine, regid, cast(void*)&value);
        if (status != Status.OK)
            throw new UnicornError(format("Error: %s", uc_strerror(status).fromStringz));
        return value;
    }

    void memMap(ulong address, size_t size, uint perms)
    {
        auto status = uc_mem_map(this.engine, address, size, perms);
        if (status != Status.OK)
            throw new UnicornError(format("Error: %s", uc_strerror(status).fromStringz));
    }

    void memUnmap(ulong address, size_t size)
    {
        auto status = uc_mem_unmap(this.engine, address, size);
        if (status != Status.OK)
            throw new UnicornError(format("Error: %s", uc_strerror(status).fromStringz));
    }

    void memWrite(ulong address, const ubyte[] bytes)
    {
        auto status = uc_mem_write(this.engine, address, bytes.ptr, bytes.length);
        if (status != Status.OK)
            throw new UnicornError(format("Error: %s", uc_strerror(status).fromStringz));
    }

    ubyte[] memRead(ulong address, size_t size)
    {
        auto bytes = new ubyte[size];
        auto status = uc_mem_read(this.engine, address, bytes.ptr, size);
        if (status != Status.OK)
            throw new UnicornError(format("Error: %s", uc_strerror(status).fromStringz));
        return bytes;
    }

    void memProtect(ulong address, size_t size, uint perms)
    {
        auto status = uc_mem_protect(this.engine, address, size, perms);
        if (status != Status.OK)
            throw new UnicornError(format("Error: %s", uc_strerror(status).fromStringz));
    }

    MemRegion[] memRegions()
    {
        import core.stdc.stdlib : free;
        uint nbRegions = 0;
        const MemRegion* regionsPtr;
        auto status = uc_mem_regions(this.engine, &regionsPtr, &nbRegions);
        if (status != Status.OK)
            throw new UnicornError(format("Error: %s", uc_strerror(status).fromStringz));
        MemRegion[] regions;
        foreach (size_t i; 0 .. nbRegions)
        {
            regions ~= cast(MemRegion) *(regionsPtr[i .. i+MemRegion.sizeof]).ptr;
        }
        free(cast(void*) regionsPtr);
        return regions;
    }

    void emuStart(ulong begin, ulong until, ulong timeout, size_t count)
    {
        auto status = uc_emu_start(this.engine, begin, until, timeout, count);
        if (status != Status.OK)
            throw new UnicornError(format("Error: %s", uc_strerror(status).fromStringz));
    }

    void emuStop()
    {
        auto status = uc_emu_stop(this.engine);
        if (status != Status.OK)
            throw new UnicornError(format("Error: %s", uc_strerror(status).fromStringz));
    }

    uc_hook addCodeHook(HookType hookType, ulong begin, ulong end,
                        void function(Unicorn*, ulong, uint) callback)
    {
        uc_hook hook;
        auto user_data = new CodeHook(&this, callback);
        auto status = uc_hook_add(this.engine, &hook, hookType, cast(size_t)&code_hook_proxy,
                                  cast(size_t*)user_data, begin, end);
        if (status != Status.OK)
            throw new UnicornError(format("Error: %s", uc_strerror(status).fromStringz));
        return hook;
    }

    uc_hook addIntrHook(void function(Unicorn*, uint) callback)
    {
        uc_hook hook;
        auto user_data = new IntrHook(&this, callback);
        auto status = uc_hook_add(this.engine, &hook, HookType.INTR, cast(size_t)&intr_hook_proxy,
                                  cast(size_t*)user_data, 0, 0);
        if (status != Status.OK)
            throw new UnicornError(format("Error: %s", uc_strerror(status).fromStringz));
        return hook;
    }

    uc_hook addMemHook(HookType hookType, ulong begin, ulong end,
                       bool function(Unicorn*, MemType, ulong, size_t, long) callback)
    {
        uc_hook hook;
        auto user_data = new MemHook(&this, callback);
        auto status = uc_hook_add(this.engine, &hook, hookType, cast(size_t)&mem_hook_proxy,
                                  cast(size_t*)user_data, begin, end);
        if (status != Status.OK)
            throw new UnicornError(format("Error: %s", uc_strerror(status).fromStringz));
        return hook;
    }

    uc_hook addInsnInHook(uint function(Unicorn*, uint, size_t) callback)
    {
        uc_hook hook;
        auto user_data = new InsnInHook(&this, callback);
        auto status = uc_hook_add(this.engine, &hook, HookType.INSN, cast(size_t)&insn_in_hook_proxy,
                                  cast(size_t*)user_data, 0, 0, InsnX86.IN);
        if (status != Status.OK)
            throw new UnicornError(format("Error: %s", uc_strerror(status).fromStringz));
        return hook;
    }

    uc_hook addInsnOutHook(void function(Unicorn*, uint, size_t, uint) callback)
    {
        uc_hook hook;
        auto user_data = new InsnOutHook(&this, callback);
        auto status = uc_hook_add(this.engine, &hook, HookType.INSN, cast(size_t)&insn_out_hook_proxy,
                                  cast(size_t*)user_data, 0, 0, InsnX86.OUT);
        if (status != Status.OK)
            throw new UnicornError(format("Error: %s", uc_strerror(status).fromStringz));
        return hook;
    }

    uc_hook addInsnSysHook(InsnX86 insnType, ulong begin, ulong end,
                           void function(Unicorn*) callback)
    {
        uc_hook hook;
        auto user_data = new InsnSysHook(&this, callback);
        auto status = uc_hook_add(this.engine, &hook, HookType.INSN, cast(size_t)&insn_sys_hook_proxy,
                                  cast(size_t*)user_data, begin, end, insnType);
        if (status != Status.OK)
            throw new UnicornError(format("Error: %s", uc_strerror(status).fromStringz));
        return hook;
    }

    void removeHook(uc_hook hook)
    {
        auto status = uc_hook_del(this.engine, hook);
        if (status != Status.OK)
            throw new UnicornError(format("Error: %s", uc_strerror(status).fromStringz));
    }

    size_t query(Query query)
    {
        size_t ret = 0;
        auto status = uc_query(this.engine, query, &ret);
        if (status != Status.OK)
            throw new UnicornError(format("Error: %s", uc_strerror(status).fromStringz));
        return ret;
    }
}


template CpuImpl(Arch arch)
{
    Unicorn* emu;

    this(Mode mode)
    {
        emu = new Unicorn(arch, mode);
    }

    void regWrite(int regid, ulong value)
    {
        this.emu.regWrite(regid, value);
    }

    ulong regRead(int regid)
    {
        return this.emu.regRead(regid);
    }

    void memMap(ulong address, size_t size, uint perms)
    {
        this.emu.memMap(address, size, perms);
    }

    void memUnmap(ulong address, size_t size)
    {
        this.emu.memUnmap(address, size);
    }

    void memWrite(ulong address, const ubyte[] bytes)
    {
        this.emu.memWrite(address, bytes);
    }

    ubyte[] memRead(ulong address, size_t size)
    {
        return this.emu.memRead(address, size);
    }

    void memProtect(ulong address, size_t size, uint perms)
    {
        return this.emu.memProtect(address, size, perms);
    }

    MemRegion[] memRegions()
    {
        return this.emu.memRegions();
    }

    void emuStart(ulong begin, ulong until, ulong timeout, size_t count)
    {
        this.emu.emuStart(begin, until, timeout, count);
    }

    void emuStop()
    {
        this.emu.emuStop();
    }

    size_t query(Query query)
    {
        return this.emu.query(query);
    }

    uc_hook addCodeHook(HookType hookType, ulong begin, ulong end,
                        void function(Unicorn*, ulong, uint) callback)
    {
        return this.emu.addCodeHook(hookType, begin, end, callback);
    }

    uc_hook addIntrHook(void function(Unicorn*, uint) callback)
    {
        return this.emu.addIntrHook(callback);
    }

    uc_hook addMemHook(HookType hookType, ulong begin, ulong end,
                       bool function(Unicorn*, MemType, ulong, size_t, long) callback)
    {
        return this.emu.addMemHook(hookType, begin, end, callback);
    }

    void removeHook(uc_hook hook)
    {
        this.emu.removeHook(hook);
    }
}

struct CpuARM
{
    mixin CpuImpl!(Arch.ARM);
}

struct CpuARM64
{
    mixin CpuImpl!(Arch.ARM64);
}

struct CpuM68K
{
    mixin CpuImpl!(Arch.M68K);
}

struct CpuMIPS
{
    mixin CpuImpl!(Arch.MIPS);
}

struct CpuSPARC
{
    mixin CpuImpl!(Arch.SPARC);
}

struct CpuX86
{
    mixin CpuImpl!(Arch.X86);

    uc_hook addInsnInHook(uint function(Unicorn*, uint, size_t) callback)
    {
        return this.emu.addInsnInHook(callback);
    }

    uc_hook addInsnOutHook(void function(Unicorn*, uint, size_t, uint) callback)
    {
        return this.emu.addInsnOutHook(callback);
    }

    uc_hook addInsnSysHook(InsnX86 insnType, ulong begin, ulong end, void function(Unicorn*) callback)
    {
        return this.emu.addInsnSysHook(insnType, begin, end, callback);
    }
}


unittest
{
    // code callback
    {
        auto callback = function(Unicorn* unicorn, ulong address, uint size)
            {
                assert(address == 0x1000);
                assert(size == 1);
            };

        ubyte[] instructions = [0x41]; // INC ecx;

        auto emu = CpuX86(Mode.MODE_32);
        emu.memMap(0x1000, 0x4000, Protection.PROT_ALL);
        emu.memWrite(0x1000, instructions);

        auto hook = emu.addCodeHook(HookType.CODE, 0x1000, 0x2000, callback);
        emu.emuStart(0x1000, 0x1001, 10 * SECOND_SCALE, 1000);
        emu.removeHook(hook);
    }

    // intr callback
    {
        auto callback = function(Unicorn* unicorn, uint intno)
            {
                assert(intno == 0x80);
            };

        ubyte[] instructions = [0xcd, 0x80]; // INT 0x80;

        auto emu = CpuX86(Mode.MODE_32);
        emu.memMap(0x1000, 0x4000, Protection.PROT_ALL);
        emu.memWrite(0x1000UL, instructions);

        auto hook = emu.addIntrHook(callback);
        emu.emuStart(0x1000, 0x1000 + instructions.length, 10 * SECOND_SCALE, 1000);
        emu.removeHook(hook);
    }

    // mem callback
    {
        auto callback = function(Unicorn* unicorn, MemType memType, ulong address,
                                 size_t size, long value)
            {
                assert(memType == MemType.WRITE);
                assert(address == 0x2000);
                assert(size == 4);
                assert(value == 0xdeadbeef);
                return false;
            };

        // mov eax, 0xdeadbeef;
        // mov [0x2000], eax;
        ubyte[] instructions = [0xB8, 0xEF, 0xBE, 0xAD, 0xDE, 0xA3, 0x00, 0x20, 0x00, 0x00];

        auto emu = CpuX86(Mode.MODE_32);
        emu.memMap(0x1000, 0x4000, Protection.PROT_ALL);
        emu.memWrite(0x1000UL, instructions);

        auto hook = emu.addMemHook(cast(HookType)MemHookType.MEM_ALL, 0UL, ulong.max,
                                   callback);
        emu.regWrite(RegisterX86.EAX, 0x123);
        emu.emuStart(0x1000, 0x1000 + instructions.length, 10 * SECOND_SCALE, 0x1000);
        emu.removeHook(hook);
    }

    // insn in callback
    {
        auto callback = function(Unicorn* unicorn, uint port, size_t size)
            {
                assert(port == 0x10);
                assert(size == 4);
                return 0U;
            };

        ubyte[] instructions = [0xe5, 0x10]; // IN eax, 0x10;

        auto emu = CpuX86(Mode.MODE_32);
        emu.memMap(0x1000, 0x4000, Protection.PROT_ALL);
        emu.memWrite(0x1000UL, instructions);

        auto hook = emu.addInsnInHook(callback);
        emu.emuStart(0x1000, 0x1000 + instructions.length, 10 * SECOND_SCALE, 1000);
        emu.removeHook(hook);
    }

    // insn out callback
    {
        auto callback = function(Unicorn* unicorn, uint port, size_t size, uint value)
            {
                assert(port == 0x46);
                assert(size == 1);
                assert(value == 0x32);
            };

        ubyte[] instructions = [0xb0, 0x32, 0xe6, 0x46]; // MOV al, 0x32; OUT  0x46, al;

        auto emu = CpuX86(Mode.MODE_32);
        emu.memMap(0x1000, 0x4000, Protection.PROT_ALL);
        emu.memWrite(0x1000UL, instructions);

        auto hook = emu.addInsnOutHook(callback);
        emu.emuStart(0x1000, 0x1000 + instructions.length, 10 * SECOND_SCALE, 1000);
        emu.removeHook(hook);
    }

    // insn sys callback
    {
        auto callback = function(Unicorn* unicorn)
            {
                auto rax = unicorn.regRead(RegisterX86.RAX);
                assert(rax == 0xdeadbeef);
            };

        // MOV rax, 0xdeadbeef; SYSCALL;
        ubyte[] instructions = [0x48, 0xB8, 0xEF, 0xBE, 0xAD, 0xDE, 0x00, 0x00, 0x00, 0x00, 0x0F,
                                0x05];

        auto emu = CpuX86(Mode.MODE_64);
        emu.memMap(0x1000, 0x4000, Protection.PROT_ALL);
        emu.memWrite(0x1000UL, instructions);

        auto hook = emu.addInsnSysHook(InsnX86.SYSCALL, 1, 0, callback);
        emu.emuStart(0x1000, 0x1000 + instructions.length, 10 * SECOND_SCALE, 1000);
        emu.removeHook(hook);
    }
}
