# What it is
Kinda like a reflective loader, this runs Mach-O binaries (including Fat Mach-O) straight in memory.
No execve.
Right now it only works with statically linked binaries, because I’m still figuring out how to honor fixed chain ups properly.