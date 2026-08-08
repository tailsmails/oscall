# oscall

A native, low-level CLI utility written in V for inspecting, loading, and dynamically executing arbitrary C/C++ functions within shared libraries (`.so`) on Linux and Android (both 32-bit and 64-bit) environments.

`oscall` is designed for platform developers, hardware diagnostic engineers, and security researchers who need to interact with internal, stripped, or dynamically registered vendor APIs directly from the command line without compiling custom wrapping code.

---

## Technical Overview

`oscall` operates by bypassing traditional high-level JVM constraints and interfacing directly with the native execution layers. It bridges the gap between static binary analysis and active dynamic invocation.

Under the hood, the execution cycle follows these steps:
1. **Dynamic Loading:** The target library is mapped into the memory space of `oscall` using POSIX dynamic linking interfaces.
2. **Memory Map Parsing:** The utility reads `/proc/self/maps` of its own active process to resolve the base virtual memory load address of the target library.
3. **Architecture Detection & ELF Parsing:** It reads the ELF class identifier from the physical binary, dynamically adapts to parse either ELF32 or ELF64 structures, and traverses the Section Headers.
4. **Symbol Table Fallback:** It scans the static symbol table (`.symtab`). If the binary has been stripped, it automatically falls back to parsing the dynamic symbol table (`.dynsym`).
5. **Absolute Pointer Resolution:** By matching the target symbol, it extracts the relative file offset and combines it with the base memory map address (`Base Address + Offset`), bypassing `dlsym` limitations on unexported or local C++ symbols (e.g., `_ZL` static functions).
6. **Execution Pipeline Chaining:** Using the execution delimiter (`::`), the utility decomposes the CLI instructions into sequential steps, keeping the runtime environment intact.
7. **Dynamic ABI Casting & Output Formatting:** Based on user-provided CLI arguments, it dynamically casts the absolute memory pointer to a corresponding function signature (from 0 to 12 arguments), triggers execution, and intercepts the return value to cast it into the specified output format.
8. **State Preservation:** Registers named memory heap buffers across execution steps, allowing consecutive functions to reference and manipulate persistent objects.

---

## Key Features

- **Multi-Arch ELF Parser:** Built-in low-level ELF parser supporting both 32-bit (ELF32) and 64-bit (ELF64) symbol matching and extraction from `.symtab` and `.dynsym`.
- **Dynamic ABI Binder:** Call delegates supporting up to 12 arguments mapping to standard ARM/ARM64 and x86/x86_64 calling conventions.
- **On-the-fly Return Formatting:** Casts and prints return values dynamically using runtime format indicators (`->int`, `->string`, `->bool`).
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

### Return Value Formatting

To interpret and display the return value of a step, append one of the following formatting flags to the arguments. 

*(Note: Always wrap formatting flags in quotes like `"->string"` or escape them as `-\>string` to prevent the shell from interpreting the `>` character as an output redirection).*

| Flag | Example | Description |
| :--- | :--- | :--- |
| `"->hex"` | `"->hex"` | Interprets the return value as a raw hexadecimal address/value (Default). |
| `"->string"` | `"->string"` | Safely dereferences the return pointer and prints it as a null-terminated C-string. |
| `"->int"` | `"->int"` | Interprets the return value as a signed 64-bit integer (`int64`). |
| `"->bool"` | `"->bool"` | Evaluates the return value as a boolean (`true`/`false`). |

---

## Practical Examples

### 1. Listing All Available Symbols in a Shared Library
To scan and print the complete offset table of a library:
```bash
./oscall libc.so --list
```

### 2. Basic Arithmetic and Value Interpretation
To call a function and format the return value directly as a signed integer:
```bash
./oscall libc.so geteuid "->int"
```
**Output:**
```text
[!] === Executing Step 1 (geteuid) ===
[+] Symbol Offset: 0x00000000000e56d0
[+] Target Memory Address: 0x7538f256d0
[!] Calling function with 0 args...
[+] Return (Int): 10327
```

### 3. Resolving Environment Strings (Pointer Dereferencing)
To call `getenv("PATH")` which returns a memory address containing a string, and safely print the referenced string:
```bash
./oscall libc.so getenv s:PATH "->string"
```
**Output:**
```text
[!] === Executing Step 1 (getenv) ===
[+] Symbol Offset: 0x00000000000db4a0
[+] Target Memory Address: 0x7538f1b4a0
[!] Calling function with 1 args...
[+] Return (String): /sbin:/vendor/bin:/system/sbin:/system/bin
```

### 4. Reading System Parameters (Output Reference Buffer)
To call functions that expect an allocated structure or pointer to write their output directly into:
```bash
./oscall libc.so gethostname o:string 512
```

### 5. Stateful C++ Class Instantiation and Method Invocation (Chained Call)
To call C++ non-static member functions, allocate memory for the object, invoke the constructor to initialize it, and then call member functions by passing the initialized pointer as `this` (`x0` register) in a single run:
```bash
./oscall libfoo.so _ZN3FooC1Ev alloc:my_obj:512 :: _ZN3Foo7executeEii p:my_obj 10 20
```

---

## License
![License](https://img.shields.io/badge/License-EUPL1.2-red.svg)
