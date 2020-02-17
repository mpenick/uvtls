![](https://github.com/mpenick/uvtls/workflows/uvtls%20CI/badge.svg)

# uvtls

## Overview 

TLS/SSL extension for [libuv] that tries to conform to its style and idioms.
If you're used to using libuv then it should be easy for you to pick up uvtls
and integrate it into your application.

## To build

```
mkdir build
cd build
cmake ..
make
```

## To build with vcpkg on Windows
```
vcpkg install openssl-windows
vcpkg install libuv
mkdir build
cd build
cmake ..
make
```

## Features

* Client-side support
* Server-side support
* OpenSSL integration

## Work in progress

This is a work in-progress and is currently pre-alpha quality software. I'm
currently working on the following:

* [Tests](/tests)
* [Examples](/examples)
* Documentation
* API refinement
* Support for other TLS/SSL libraries

## Contributing

Please feel free to contribute issues and PRs! Please run `clang-format` on your
code before submitting.

## Examples

Look in the [examples](/examples) directory (more to come soon).

[libuv]: https://github.com/libuv/libuv
