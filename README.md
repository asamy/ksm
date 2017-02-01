# ksm v1.6-dev [![BountySource](https://www.bountysource.com/badge/team?team_id=189129&style=raised)](https://www.bountysource.com/teams/ksm?utm_source=ksm&utm_medium=shield&utm_campaign=raised) [![Build Status](https://travis-ci.org/asamy/ksm.svg?branch=master)](https://travis-ci.org/asamy/ksm) [![Build Status](https://ci.appveyor.com/api/projects/status/nb7u22qxjabauex5?svg=true)](https://ci.appveyor.com/project/asamy/ksm)

A really simple and lightweight x64 hypervisor written in C for Intel processors.  
KSM has a self-contained physical memory introspection engine and userspace physical
memory virtualization which can be enabled at compiletime.

Currently, KSM runs on Windows and Linux kernels natively, and aims to support
macOS by 2017, if you want to port KSM see `Documentation/SPEC.rst` for more information.

Unlike other hypervisors (e.g. KVM, XEN, etc.), KSM's purpose is not to run
other Operating Systems, instead, KSM can be used as an extra layer of
protection to the existing running OS.  This type of virtualization is usually
seen in Anti-viruses, or sandboxers or even Viruses.  KSM also supports
nesting, that means it can emulate other hardware-assisted virtualization tools
(VT-x) such as KVM or itself, it's however an experimental feature and
is not recommended.

## Usage under Linux (+sandbox)

[![asciicast](https://asciinema.org/a/10cu6v7c6l0j4532cww8tq1a1.png)](https://asciinema.org/a/10cu6v7c6l0j4532cww8tq1a1)

## Features

- IDT Shadowing
- EPT violation #VE (enabled only when support is present)
- EPTP switching VMFUNC (if not available natively, it will be emulated using a VMCALL)
- Builtin Userspace physical memory sandboxer (Optional)
- Builtin Introspection engine (Optional)
- APIC virtualization (Experimental, do not use)
- VMX Nesting (Experimental, do not use)

## Requirements

- An Intel processor (with VT-x and EPT support)
- A working C compiler (GCC or Microsoft compiler aka CL are supported)

## Supported Kernels

- All x64 NT kernels starting from the Windows 7 NT kernel.  It was mostly tested under Windows 7/8/8.1/10.
- Linux kernel (tested under 3.16, 4.8.13 and mainline)

If you have tested it under another kernel version, please create an issue so
it can be added here.

## Hacking KSM

Few examples are included to illustrate usage and show how to integrate modules
into it, some of which are sandbox.c and introspect.c, those are mainly not
very useful right now, but they will be extended later, so feel free to
contribute your ideas or code.  

## Technical Documentation

See Documentation/SPEC.rst

## Contributions

See Documentation/CONTRIBUTIONS.rst

## Building / Usage

See Documentation/BUILDING.rst

## Issues (bugs, features, etc.)

Feel free to use Github Issues, there is an Issue Template to help you file
things as required.

## References

- Linux kernel (KVM)
- HyperPlatform
- XEN

## License

GPL v2 firm, see LICENSE file.  Note that some code is thirdparty, respective
licenses and/or copyright should be there, if you think it's not, please let me
know.  Most of the code is GPL'd, though...

