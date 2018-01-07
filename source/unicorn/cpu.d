module unicorn.cpu;

import std.exception;
import std.format;
import std.string : fromStringz;
import std.typecons : tuple;

import unicorn.constants;
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
alias MemHook = UnicornHook!(bool function(Unicorn*, MemType, ulong, size_t, ulong));
alias InsnInHook = UnicornHook!(uint function(Unicorn*, uint, size_t));
alias InsnOutHook = UnicornHook!(void function(Unicorn*, uint, size_t, uint));
alias InsnSysHook = UnicornHook!(void function(Unicorn*));

extern (C) void code_hook_proxy(uc_handle _, uint address, uint size, CodeHook* user_data)
{
    (*user_data.callback)(user_data.unicorn, address, size);
}

extern (C) void intr_hook_proxy(uc_handle _, uint intno, IntrHook* user_data)
{
    (*user_data.callback)(user_data.unicorn, intno);
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

    size_t query(Query query)
    {
        size_t ret = 0;
        auto status = uc_query(this.engine, query, &ret);
        if (status != Status.OK)
            throw new UnicornError(format("Error: %s", uc_strerror(status).fromStringz));
        return ret;
    }
}

unittest
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

    uc_hook addIntrHook(void function(Unicorn*, uint) callback)
    {
        return this.emu.addIntrHook(callback);
    }
}

struct CpuARM
{
    mixin CpuImpl!(Arch.ARM);
}

struct CpuX86
{
    mixin CpuImpl!(Arch.X86);
}
