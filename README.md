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
6. **Execution Pipeline Chaining:** Using the execution delimiter (`::`), the utility decomposes the CLI instructions into sequential steps, keeping the runtime environment intact.
7. **Dynamic ABI Casting:** Based on user-provided CLI arguments, it dynamically casts the absolute memory pointer to a corresponding function signature (from 0 to 12 arguments) and triggers execution.
8. **State Preservation:** Registers named memory heap buffers across execution steps, allowing consecutive functions to reference and manipulate persistent objects.

---

## Key Features

- **ELF64 Parser:** Built-in low-level ELF parser supporting symbol matching and extraction from `.symtab` and `.dynsym`.
- **Dynamic ABI Binder:** Call delegates supporting up to 12 arguments mapping to the standard ARM64/x86_64 calling conventions.
- **Symbol Enumeration:** Quick directory/listing of all exported and internal symbols of any mapped library.
- **Chained Execution Pipeline:** Sequential execution of multiple native functions in a single process run using the `::` delimiter.
- **Stateful Memory Binding:** Persistent heap allocation (`alloc:`) and reference tracking (`p:`) to simulate complex object initialization and lifecycle management.
- **Piped Return Registering:** Reference and pass the raw or pointer-casted return values of previous execution steps (`$1`, `$2`, etc.) as arguments to subsequent functions.
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
oscall <lib_name_or_path> <symbol_name> [args] :: <symbol_name_2> [args] :: ...
oscall <lib_name_or_path> --list
```

### Argument Prefixes and Types

`oscall` treats command-line arguments as 64-bit register values (`voidptr`). To define pointers, strings, or buffers, use the following syntax:

| Prefix | Example | Description |
| :--- | :--- | :--- |
| *(None)* | `123` | Passed as a raw 64-bit integer (`int`). |
| `p:` | `p:0x7a41` | Parsed as a hex address and passed as a raw memory pointer. Use `p:0x0` for `nullptr`. |
| `s:` | `s:my_text` | Allocates a null-terminated C-string in memory and passes its pointer. |
| `alloc:name:size` | `alloc:my_buf:64` | Allocates a persistent `size`-byte buffer on the heap, registered under `name`, and passes its pointer. |
| `p:name` | `p:my_buf` | Looks up the registered heap buffer `name` and passes its memory pointer. |
| `$1`, `$2`... | `$1` | Passes the raw 64-bit return value of Step 1, Step 2, etc. |
| `p:$1`, `p:$2`... | `p:$1` | Passes the 64-bit return value of Step 1, Step 2, etc., cast as a pointer. |
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

### 4. Stateful C++ Class Instantiation and Method Invocation (Chained Call)
To call C++ non-static member functions, you can allocate memory for the object, invoke the constructor to initialize it, and then call member functions by passing the initialized pointer as `this` (`x0` register) in a single run:
```bash
sudo ./oscall libem_wifi_jni.so _ZN7android7CMT66xxC1Ev alloc:my_chip:1024 :: _ZN7android7CMT66xx18HQA_DBDCStartRXExtEiiii p:my_chip 1 2 3 4
```
**Execution Sequence:**
1. **Step 1:** Allocates `1024` bytes on the heap (registered as `my_chip`) and calls the constructor `android::CMT66xx::CMT66xx()` with `my_chip` as its implicit `this` pointer to initialize the class in memory.
2. **Step 2:** Resolves the offset of `HQA_DBDCStartRXExt` and executes it, passing the initialized `my_chip` pointer as the first argument, followed by the remaining parameters.

---

## License
![License](https://img.shields.io/badge/License-EUPL1.2-red.svg)
