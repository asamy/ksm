Building
========

Enabling certain features / tests
---------------------------------

You can define one or more of the following:

- `INTROSPECT_ENGINE` - Enables a tiny physical memory introspection engine
- `PMEM_SANDBOX` - Enables userspace physical memory virtualizer
- `EPAGE_HOOK` - Enables executable page shadow hook
- `ENABLE_PML` - Enables Page Modification Log if supported.
- `EMULATE_VMFUNC` - Forces emulation of VMFUNC even if CPU supports it.
- `EPT_SUPPRESS_VE` - Force suppress VE bit in EPT.
- `ENABLE_RESUBV` - Enable S1-3-S4 power state monitoring for re-virtualization
- `NESTED_VMX` - Enable experimental VT-x nesting
- `ENABLE_FILEPRINT` - Available on Windows only.  Enables loggin to disk
- `ENABLE_DBGPRINT` - Available on Windows only.  Enables `DbgPrint` log.
- `VCPU_TRACER_LOG` - Outputs a useless message on some VM-Exit handlers, this can be replaced with something more useful such as performance measurements, etc.  See `ksm.h` for more information.

Building for Linux
------------------

Install kernel headers:

- Debian/Ubuntu: `[sudo] apt-get install linux-headers-$(uname -r)`
- ArchLinux: `[sudo] pacman -S linux-headers`
- Fedora: `[sudo] yum install kernel-devel kernel-headers`

Targets:

- `all` - Build the kernel module and the userspace app
- `umk` - Build the userspace app only
- `dri` - Build the kernel module only
- `clean` - Clean everything
- `install` - Installs to kernel module dir (root required)
- `load` - Load the kernel module (root required)
- `unload` - Unload the kernel module (root required)

Then `make <TARGET>`, e.g.: `make umk` (all is default).

Building for Windows
--------------------

Under MinGW
----------------------

	**Warning**: The MinGW build is known to be unstable under Windows 10, so it's
	not recommended, rather use the VS project to compile for Windows.

Makefile variables
-------------------

You can pass one or more of the following variables to your `make` command:

- `WINVER=0x0602` - Explicility specify windows version to build for.
- `C=1` - Prepare for cross-compiling.
- `Q=1` - Be quiet.
- `BIN_DIR=arg` - Generate binary and symbols to this directory
- `OBJ_DIR=arg` - Generate object files to this directory
- `DEP_DIR=arg` - Generate dependency files to this directory
- `CROSS_INC=arg` - Path to include directory if they reside in a special place
- `CROSS_LIB=arg` - Path to library directory if they reside in a special place
- `CROSS_BUILD=arg` - Prefix to toolchain binaries (e.g. `x86-_64-w64-mingw32-`)

Targets:

- `all` - Builds the driver and the usermode app
- `umk` - Build just the usermode app
- `dri` - Build just the driver
- `clean` - Clean everything

You may need to adjust the windows version you're compiling for, in that case
adjust `WINVER` inside the Makefile manually or pass it through commandline:

	make -f Makefile.windows C=1 WINVER=0x0602 all

Cross under Linux
-----------------

Install the following packages:

- Debian/Ubuntu: `[sudo] apt-get install gcc-mingw-w64-x86-64 binutils-mingw-w64-x86-64`
- ArchLinux: `[sudo] pacman -S mingw-w64-gcc`
- Fedora: `[sudo] yum install mingw64-gcc`

Then `make -f Makefile.windows C=1 all`

Under Native
------------

Natively, you'll want to adjust (or pass in command line) DDK paths, e.g.:

	`mingw32-make -f Makefile.windows CROSS_INC=/path/to/include/ddk all`

Or, simply just edit Makefile.windows manually.  Also make sure to adjust your
environment variables (PATH) to point to the right `bin/` directory where the
compiler, etc lie.

Compiling under MSVC
--------------------

The solution under `ksm/` directory is a VS 2015 solution.

To build it under MSVC, you'll need the following:

1. VS2015_
2. SDK_
3. WDK_

.. _VS2015: https://www.visualstudio.com/downloads/
.. _SDK: https://developer.microsoft.com/en-us/windows/downloads/windows-10-sdk
.. _WDK: https://developer.microsoft.com/en-us/windows/hardware/windows-driver-kit

	**NOTE**:  You need to adjust the Windows version you are targetting via the
	project properities when inside Visual Studio, right click the Project (`ksm`)
	then go to Driver Settings -> General -> Target OS Version.

	Then you can build it via either the VS interface (right click the project then build),
	or the hardway if you prefer, from VS command line, simply cd to where `ksm` is and:

	msbuild ksm\ksm.sln

Or:

	msbuild ksm\ksm\ksm.vcxproj

Loading the driver
------------------

On Linux:

        - Load: `sudo make load`
        - Unload: `sudo make unload`
        - Output: `sudo dmesg -wH`

On Windows:

In commandline as administrator:

1. `sc create ksm type= kernel binPath= C:\path\to\your\ksm.sys`
2. `sc start ksm`

Unloading:

- `sc stop ksm`

	Output can be seen via DebugView or WinDBG if live debugging
	Note: You might want to execute `ed Kd_DEFAULT_Mask 8` to see any output.

	**Note for Windows 10**: DebugView seems to be having problems starting a 2nd
	time there, to workaround this, rename it's driver
	`C:\windows\system32\drivers\Dbgv.sys` to something else, then start it again.

Using the driver
----------------

	Since you started it, it does nothing, it's waiting for the usermode app to
	instruct it, to do so, run the usermode app as root/admin which will run an
	IOCTL to the driver to tell it to virtualize the system, then you can give it
	Process Identifiers (PIDs) to sandbox.

