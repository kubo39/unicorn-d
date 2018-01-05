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
}
