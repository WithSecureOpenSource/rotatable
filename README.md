## Overview

rotatable is a C library for Linux-like operating systems that offers a
generic log file rotation facility.

## Building

rotatable uses [SCons][] and `pkg-config` for building.

Before building rotatable for the first time, run
```
git submodule update --init
```

To build rotatable, run
```
scons [ prefix=<prefix> ]
```
from the top-level rotatable directory. The optional prefix argument is a
directory, `/usr/local` by default, where the build system installs
rotatable.

To install rotatable, run
```
sudo scons [ prefix=<prefix> ] install
```

## Documentation

The header files under `include` contain detailed documentation.

[SCons]: https://scons.org/
