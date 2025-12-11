# What it is
Kinda like a reflective loader, this runs Mach-O binaries (including Fat Mach-O) straight in memory.
No execve.
Right now it only works with statically linked binaries, because I’m still figuring out how to honor fixed chain ups properly.

# Links
- https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h
- https://leopard-adc.pepas.com/documentation/DeveloperTools/Conceptual/MachORuntime/Reference/reference.html
- https://leopard-adc.pepas.com/documentation/DeveloperTools/Reference/MachOReference/Reference/reference.html
- https://leopard-adc.pepas.com/documentation/DeveloperTools/Reference/MachOReference/MachOReference.pdf
- https://www.cs.miami.edu/home/burt/learning/Csc521.091/docs/MachOTopics.pdf
- https://www.newosxbook.com/articles/DYLD.html
- https://github.com/facebook/fishhook
- https://grokipedia.com/page/Mach-O
- https://www.objc.io/issues/6-build-tools/mach-o-executables/
- https://www.newosxbook.com/MOXiI.pdf
- https://blog.darlinghq.org/2018/07/mach-o-linking-and-loading-tricks.html
- https://developer.apple.com/library/archive/documentation/DeveloperTools/Conceptual/DynamicLibraries/000-Introduction/Introduction.html