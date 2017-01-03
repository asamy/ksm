# Building

## Building for Linux

Install kernel headers:

- Debian/Ubuntu: `[sudo] apt-get install linux-headers-$(uname -r)`
- ArchLinux: `[sudo] pacman -S linux-headers`
- Fedora: `[sudo] yum install kernel-devel kernel-headers`

Then `make`.

## Building for Windows

### Compiling under MinGW

**Warning**: The MinGW build is known to be unstable under Windows 10, so it's
not recommended, rather use the VS project to compile for Windows.

#### Makefile variables:

You can pass one or more of the following variables to your `make` command:

- `WINVER=0x0602` - Explicility specify windows version to build for.
- `C=1` - Prepare for cross-compiling.
- `V=1` - Verbose output (the default, pass 0 for quiet.)
- `BIN_DIR=arg` - Generate binary and symbols to this directory
- `OBJ_DIR=arg` - Generate object files to this directory
- `DEP_DIR=arg` - Generate dependency files to this directory
- `CROSS_INC=arg` - Path to include directory if they reside in a special place
- `CROSS_LIB=arg` - Path to library directory if they reside in a special place
- `CROSS_BUILD=arg` - Prefix to toolchain binaries (e.g.
						    `x86-_64-w64-mingw32-XXX`)
- `PREPEND=arg` - Prepend something to the compiler/linker executable (e.g. if
								       this is
								       "c" and
								       compiler
								       is "gcc"
								       then
								       full
								       command
								       is going
								       to be
								       "cgcc")
- `CEXTRA=arg` - Print something out after compiling a C file.
- `AEXTRA=arg` - Print something out after compiling an Assembler file.
- `LEXTRA=arg` - Print something out after linking

You may need to adjust the windows version you're compiling for, in that case
adjust `WINVER` inside the Makefile manually or pass it through commandline:

	make -f Makefile.windows C=1 WINVER=0x0602

#### Cross under Linux

Install the following packages:

- Debian/Ubuntu: `[sudo] apt-get install gcc-mingw-w64-x86-64
binutils-mingw-w64-x86-64`
- ArchLinux: `[sudo] pacman -S mingw-w64-gcc`
- Fedora: `[sudo] yum install mingw64-gcc`

Then `make -f Makefile.windows C=1`

#### Under Native

Natively, you'll want to adjust (or pass in command line) DDK paths, e.g.:

`mingw32-make -f Makefile.windows CROSS_INC=/path/to/include/ddk`

Or, simply just edit Makefile.windows manually.  Also make sure to adjust your
environment variables (PATH) to point to the right `bin/` directory where the
compiler, etc lie.

### Compiling under MSVC

The solution under `ksm/` directory is a VS 2015 solution, you can use it to build, you'll
also need the Windows Driver Development Kit.

**NOTE**:  You need to adjust the Windows version you are targetting via the
project properities, go to Driver Settings -> General -> Target OS Version.

To build from VS command line, simply cd to where `ksm` is and:

`msbuild ksm\ksm.sln`

Or:

`msbuild ksm\ksm\ksm.vcxproj`

