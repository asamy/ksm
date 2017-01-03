# ksm v1.4 [![BountySource](https://www.bountysource.com/badge/team?team_id=189129&style=raised)](https://www.bountysource.com/teams/ksm?utm_source=ksm&utm_medium=shield&utm_campaign=raised) [![Build Status](https://travis-ci.org/asamy/ksm.svg?branch=master)](https://travis-ci.org/asamy/ksm) [![Build Status](https://ci.appveyor.com/api/projects/status/nb7u22qxjabauex5?svg=true)](https://ci.appveyor.com/project/asamy/ksm)

A really simple and lightweight x64 hypervisor written in C for Intel processors.

KSM aims to be fully feature fledged and as general purpose as possible,
although there are absolutely no barriers, even extending it to be a
multi-purpose thing is perfeclty fine, e.g. a sandbox, etc.

Currently, KSM runs on Windows and Linux kernels natively, and aims to support
macOS by 2017, if you want to port KSM see porting guidelines down below.  Note
that the `master` branch may be unstable (bugs, unfinished features, etc.), so
you might want to stick with the releases for a captured stable state.

Unlike other hypervisors (e.g. KVM, XEN, etc.), KSM's purpose is not to run
other Operating Systems, instead, KSM can be used as an extra layer of
protection to the existing running OS.  This type of virtualization is usually
seen in Anti-viruses, or sandboxers or even Viruses.  KSM also supports
nesting, that means it can emulate other hardware-assisted virtualization tools
(VT-x) such as KVM or itself, it's however an experimental feature and
is not recommended.

## Features

- IDT Shadowing
- EPT violation #VE (if not available natively, VM-exit path is taken)
- EPTP switching VMFUNC (if not available natively, it will be emulated using a VMCALL)
- APIC virtualization (Experimental, do not use)
- VMX Nesting (Experimental, do not use)

## Why not other hypervisors?

You may have already guessed from the `Features` part, if not, here are some reasons:

- Do not implement the new processor features KSM implements (VMFUNC, #VE, etc.)
- Are not simple enough to work with or understand
- Simply, just have messy code base or try too hard to implement endless C++ features that just make code ugly.
- Too big code base and do not have the same purpose (e.g. research or similar)

Such features for my purpose were really cruical, I needed a quicker physical memory virtualization technique
that I can relay on.

## Requirements

- An Intel processor (with VT-x and EPT support)
- A working C compiler (GCC or Microsoft compiler aka CL are supported)

## Supported Kernels

- All x64 NT kernels starting from the Windows 7 NT kernel.  It was mostly tested under Windows 7/8/8.1/10.
- Linux kernel (tested under 3.16, 4.8.13 and mainline)

## TODO / In development

- APIC virtualization (Partially implemented, needs testing & fixes)
- TSC virtualization
- UEFI support
- Intel TXT support
- AMD-V with NPT support
- Nesting support (Some fixes needed and support for minor features)
- More documentation
- Finish writing tests
- Failsafe state (e.g. when an unexpected thing happens, turn off and restore
                  state to a valid one.)

See also Github issues.  Some of these features are unfortunately not
(fully) implemented due to lack of hardware (support) or similar.

## Technical Documentation

See Documentation/SPEC.md

## Contributions

See Documentation/CONTRIBUTIONS.md

## Building

See Documentation/BUILDING.md

## Loading the driver

### On Linux
Loading:
- `sudo make load`  

Unloading:
- `sudo make unload`

Output:
- `sudo dmesg -wH`

### On Windows
In commandline as administrator:

1. `sc create ksm type= kernel binPath= C:\path\to\your\ksm.sys`
2. `sc start ksm`

Unloading:
- `sc stop ksm`

You can also use [kload](https://github.com/asamy/kload)  
Output can be seen via DebugView or WinDBG if live debugging (You might want to
							      execute `ed
							      Kd_DEFAULT_Mask
							      8`).

**Note for Windows 10**: DebugView seems to be having problems starting a 2nd
time there, to workaround this, rename it's driver
C:\windows\system32\drivers\Dbgv.sys to something else, then start it again.

## Reporting bugs (or similar)

You can report bugs using Github issues, there is an Issue Template to help you
fill things as needed.

## References

- Linux kernel (KVM)
- HyperPlatform
- XEN

## License

GPL v2 firm, see LICENSE file.  Note that some code is thirdparty, respective
licenses and/or copyright should be there, if you think it's not, please let me
know.  Most of the code is GPL'd, though...

