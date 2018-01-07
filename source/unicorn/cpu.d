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
}

struct CpuARM
{
    mixin CpuImpl!(Arch.ARM);
}

struct CpuX86
{
    mixin CpuImpl!(Arch.X86);
}
