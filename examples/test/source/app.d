import std.stdio;
import unicorn;

void main()
{
    auto ver = unicornVersion();
    writefln("unicorn version: %d.%d", ver[0], ver[1]);
    writeln("IsARM supported?: ", archSupported(Arch.X86));

    auto emu = new CpuARM(Mode.THUMB);
    auto pageSize = emu.query(Query.PAGE_SIZE);
    writefln("page size: %u", pageSize);
    auto mode = emu.query(Query.MODE);
    writefln("hardware mode: %u", mode);

    emu.memMap(0x10000, 0x4000, Protection.PROT_ALL);
    auto regions = emu.memRegions();
    writefln("Regions: %u", regions.length);

    foreach (region; regions)
        writeln(region);
}
