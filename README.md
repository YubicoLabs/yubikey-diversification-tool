# yubikey-diversification-tool

This tool provides an example implementation of the diversification used by Yubico to pre-personalize YubiKeys with a customer supplied master key.

## Dependencies

- OpenSSL v1.0.0+
- CMake 3.1+
- Any C++14 compatible compiler
- Vcpkg (Windows only)

## Building

This example tool uses CMake to build the C++ on almost every platform that supports it and OpenSSL.

### Windows
We have chosen [VcPkg](https://github.com/microsoft/vcpkg) to manage dependencies on Windows.

1. Install VcPkg on your machine and make sure VCPKG_ROOT is set in your PATH. See the [VcPkg](https://github.com/microsoft/vcpkg#quick-start-windows) project documentation.
2. Integrating VcPkg into VSCode or Visual Studio with CMake support makes finding packages installed by VcPkg very easy, using its CMake toolchain file (see CMakePresets.json)
3. Install OpenSSL via VcPkg, so CMake can find it, e.g.:
   ```
   > vcpkg install openssl:x64-windows
   ```
4. If using VsCode or Visual Studio, configure CMake using the "Debug - Win64" preset.

### Linux/MacOS
OpenSSL (libcrypto) is already present on these systems.

1. Create a build directory in the repository root (e.g, build).
2. Configure the build using your system defaults.
   ```
   > cd build
   > cmake ..
   ```
3. Build the project.
   ```
   > cmake --build . --target install
   ```

## Running the tool
The tool can either take specific input for the parameters to the Yubico implementation of a SP800-108 KDF using AES_CMAC_256 or randomize these arguments to generate test vectors.

For example, the following command will randomize the master key, diversification data prefix and serial number used as input to AES_CMAC_256 for all supported labels.
```
> yubikey-diversification-tool -k random -s random -p random

Using BMK: 932bd0c111c77735808befddc145b2b530f6af7e2a33764084d2210b7734e277
Using Diversification Data: 5c6c42aafeb5d5373ee1

Label: ISD_DAK (00000001), Value (16 bytes, Binary): dab699b33ad434602fee666f0a3b59c2
Label: ISD_DMK (00000002), Value (16 bytes, Binary): 2bef70872b0c3a6f6ffe910afff335e1
Label: ISD_DEK (00000003), Value (16 bytes, Binary): 0356916405e6d1a450ebfc0fa6f23b87
Label: PIV_ADMIN (00000004), Value (24 bytes, Binary): 5b32e0265c9651b245c4fc661b2362407896fd091d304ccc
Label: PIV_PIN (00000006), Value (6 chars, Number): 494332
Label: PIV_PUK (00000007), Value (8 chars, Number): 06328101
Label: CONFIG_LOCK (00000010), Value (16 bytes, Binary): 1ad1d4d5b30870b8b68edc94e1a05b5b
Label: U2F_PIN (00000080), Value (6 chars, Number): 457572
Label: OPGP_PW1 (00000081), Value (6 chars, Number): 893459
Label: OPGP_PW3 (00000082), Value (8 chars, Number): 43785482
Label: OPGP_ADMIN (00000083), Value (16 bytes, Binary): 3e89d3eb496e70a35c108c7aa5ce5174
Label: OATH_ADMIN (00000084), Value (16 bytes, Binary): 7038e97a6265479ef35cb6452ef2fd30
Label: OATH_CRED0 (000000c0), Value (20 bytes, Binary): ce7e81c6eeac5db43c26878166d0bc61367ece25
```

More information is available using the -h command line parameter.

## License
This tool is provided free of charge under the Apache 2.0 license, found in the LICENSE file of this repository.