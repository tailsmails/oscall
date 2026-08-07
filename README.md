# oscall

A native, low-level CLI utility written in V for inspecting, loading, and dynamically executing arbitrary C/C++ functions within shared libraries (`.so`) on Linux and Android environments.

`oscall` is designed for platform developers, hardware diagnostic engineers, and security researchers who need to interact with internal, stripped, or dynamically registered vendor APIs directly from the command line without compiling custom wrapping code.

---

## Technical Overview

`oscall` operates by bypassing traditional high-level JVM constraints and interfacing directly with the native execution layers. It bridges the gap between static binary analysis and active dynamic invocation.

Under the hood, the execution cycle follows these steps:
1. **Dynamic Loading:** The target library is mapped into the memory space of `oscall` using POSIX dynamic linking interfaces.
2. **Memory Map Parsing:** The utility reads `/proc/self/maps` of its own active process to resolve the base virtual memory load address of the target library.
3. **ELF Parsing:** It opens the physical binary, parses the ELF64 headers on disk, and traverses the Section Headers.
4. **Symbol Table Fallback:** It scans the static symbol table (`.symtab`). If the binary has been stripped, it automatically falls back to parsing the dynamic symbol table (`.dynsym`).
5. **Absolute Pointer Resolution:** By matching the target symbol, it extracts the relative file offset and combines it with the base memory map address (`Base Address + Offset`), bypassing `dlsym` limitations on unexported or local C++ symbols (e.g., `_ZL` static functions).
6. **Dynamic ABI Casting:** Based on user-provided CLI arguments, it dynamically casts the absolute memory pointer to a corresponding function signature (from 0 to 12 arguments) and triggers execution.

---

## Key Features

- **ELF64 Parser:** Built-in low-level ELF parser supporting symbol matching and extraction from `.symtab` and `.dynsym`.
- **Dynamic ABI Binder:** Call delegates supporting up to 12 arguments mapping to the standard ARM64/x86_64 calling conventions.
- **Symbol Enumeration:** Quick directory/listing of all exported and internal symbols of any mapped library.
- **Reference / Output Capture:** Specialized runtime buffer allocation (`o:int` and `o:string`) to pass references as arguments and print the values modified by the native functions after execution.

---

## Compilation

Ensure you have the V compiler installed. To cross-compile for Android (ARM64) from your development machine:

```bash
v -os android -arch arm64 oscall.v -o oscall
```

To compile natively on Linux:

```bash
v oscall.v -o oscall
```

---

## Usage

```bash
oscall <lib_name_or_path> <symbol_name_or_substring> [arg1] [arg2] [arg3]...
oscall <lib_name_or_path> --list
```

### Argument Prefixes and Types

`oscall` treats command-line arguments as 64-bit register values (`voidptr`). To define pointers, strings, or buffers, use the following syntax:

| Prefix | Example | Description |
| :--- | :--- | :--- |
| *(None)* | `123` | Passed as a raw 64-bit integer (`int`). |
| `p:` | `p:0x7a41` | Parsed as a hex address and passed as a raw memory pointer. Use `p:0x0` for `nullptr`. |
| `s:` | `s:my_text` | Allocates a null-terminated C-string in memory and passes its pointer. |
| `o:int` | `o:int` | Allocates a local `int*` buffer, passes its address, and prints the updated value post-execution. |
| `o:string` | `o:string`| Allocates a 512-byte `char*` buffer, passes its address, and prints the populated string post-execution. |

---

## Practical Examples

### 1. Listing All Available Symbols in a Shared Library
To scan and print the complete offset table of a library (`apt install tsu` to use sudo or use su -c ...):
```bash
sudo ./oscall libem_wifi_jni.so --list
```

### 2. Reading Hardware Capability (Output Reference)
To call `android::CMT66xx::HQA_GetChipCapability(int* out_capability)` which expects a null class instance (`this`) as the first argument, and writes its output to the second:
```bash
sudo ./oscall libem_wifi_jni.so HQA_GetChipCapability p:0x0 o:int
```
**Output:**
```text
[+] Library Base Address: 0x0000007a4160b000
[+] Symbol Offset: 0x00000000000164b0
[+] Target Memory Address: 0x7a416214b0
[!] Executing function call...
[+] Output buffer at Argument #1 updated to: 15
```

### 3. Extracting Firmware Version string (Text Buffer Output)
To call `android::CAdapter::getFwManifestVersion(char* out_version)` which writes the firmware version to a string buffer:
```bash
sudo ./oscall libem_wifi_jni.so getFwManifestVersion p:0x0 o:string
```

---

## License
![License](https://img.shields.io/badge/License-EUPL1.2-red.svg)
