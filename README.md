# oscall

A native, low-level CLI utility written in V for inspecting, loading, and dynamically executing arbitrary C/C++ functions, as well as inspecting and patching memory of symbols within shared libraries (`.so`) on Linux and Android (both 32-bit and 64-bit) environments.

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
6. **Execution Pipeline Chaining:** Using the execution delimiter (`::`), the utility decomposes the CLI instructions into sequential steps, executing them within a single active process run.
7. **Dynamic ABI Casting & Output Formatting:** Based on user-provided CLI arguments, it dynamically casts the absolute memory pointer to a corresponding function signature (from 0 to 12 arguments), triggers execution, and intercepts the return value to cast it into the specified output format.
8. **State Preservation & Bounds Safety:** Labeled heap buffers are wrapped in a safety structure tracking both the memory pointer and the exact allocated size (`LocalBuffer`). This guarantees persistent lifecycle simulation while strictly guarding against out-of-bounds corruption.
9. **Direct Symbol Peeking & Patching:** Instead of code execution, the utility can map resolved symbol offsets (such as global variables or static configuration structs) directly to virtual memory pointers, facilitating on-the-fly visualization and values modification.

---

## Key Features

- **Multi-Arch ELF Parser:** Built-in low-level ELF parser supporting both 32-bit (ELF32) and 64-bit (ELF64) symbol matching and extraction from `.symtab` and `.dynsym`.
- **Dynamic ABI Binder:** Call delegates supporting up to 12 arguments mapping to standard ARM/ARM64 and x86/x86_64 calling conventions.
- **On-the-fly Return Formatting:** Casts and prints return values dynamically using runtime format indicators (`->int`, `->string`, `->bool`).
- **Symbol Enumeration:** Quick directory/listing of all exported and internal symbols of any mapped library.
- **Chained Execution Pipeline:** Sequential execution of multiple native functions or memory manipulation steps using the `::` delimiter.
- **Stateful Memory Binding:** Persistent heap allocation (`alloc:`) and reference tracking (`p:`) to simulate complex object initialization and lifecycle management.
- **Memory Bounds Guarding:** Integrates an internal bounds checker that validates offsets and types against the parent buffer's allocated limits prior to writing (`set:`) or reading (`dump:`), preventing heap corruption or accidental segmentation faults.
- **Direct Symbol Manipulation Engine:** Native pseudo-steps (`dump_sym:`, `set_sym:`) designed to examine and patch static global structures and variables in-memory, introducing dedicated single-precision `float` / `f32` writing.
- **Zero-initialized Allocations:** Employs POSIX `C.memset` on all heap allocations, ensuring memory states are clean and free of garbage.
- **Hex/ASCII Diagnostic Visualizer:** Safe memory inspection pseudo-command (`dump:`) validating output length boundaries and formatting raw memory spaces side-by-side.
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

### Pseudo-Step Commands

When used as discrete commands (separated by `::`), pseudo-steps manage memory layout and inspection natively:

- **`alloc:name:size`**: Allocates a zero-initialized heap buffer of `size` bytes, bound to the label `name`.
- **`set:name:offset:type:value`**: Writes `value` at `offset` inside the labeled buffer `name`.
- **`dump:name:size`**: Generates a standard hex/ASCII side-by-side memory visualizer for an allocated buffer.
- **`dump_sym:symbol_name:size`**: Reads the mapped memory location of `symbol_name` directly and outputs a standard hex/ASCII diagnostic block.
- **`set_sym:symbol_name:offset:type:value`**: Directly patches memory values at `offset` relative to the resolved address of `symbol_name`.
  - *Supported Types for `set:` and `set_sym:`:*
    - `i8` / `char` / `u8` (1 byte)
    - `i16` / `short` / `u16` (2 bytes)
    - `i32` / `int` / `u32` (4 bytes)
    - `i64` / `long` / `u64` (8 bytes) - accepts base-10 or `0x` hex strings.
    - `ptr` (8 bytes) - registers other buffer addresses, previous step outputs, or raw hex.
    - `str` - copies string bytes directly (null-terminated inline buffer).
    - `str_ptr` - writes a heap-bound char pointer to the offset (struct member pointer).
    - `float` / `f32` (4 bytes) - *Supported in `set_sym:` only*. Writes standard IEEE 754 single-precision floating-point values.

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

### 6. Inspecting and Overwriting Global Library Configurations (Dynamic Parameter Tuning)
To read, patch, and verify the memory space of a global library parameter struct without rebuilding or modifying files on disk:
```bash
./oscall libfoo.so dump_sym:global_paras:32 :: set_sym:global_paras:16:float:0.85 :: dump_sym:global_paras:32
```
**Output:**
```text
[!] === Executing Step 1 (dump_sym:global_paras:32) ===
[+] Pseudo-step: Hex/ASCII dump of symbol `global_paras` at 0x72e7a7e878 (32 bytes):
    0x00: cd cc 8c 3f cd cc 4c 3e 00 00 48 43 00 00 c8 42  | ...?..L>..HC...B
    0x10: 00 00 00 3f 00 00 a0 40 00 00 70 42 00 00 48 43  | ...?...@..pB..HC

[!] === Executing Step 2 (set_sym:global_paras:16:float:0.85) ===
[+] Pseudo-step: Written float (0.85) into symbol `global_paras` at offset 16

[!] === Executing Step 3 (dump_sym:global_paras:32) ===
[+] Pseudo-step: Hex/ASCII dump of symbol `global_paras` at 0x72e7a7e878 (32 bytes):
    0x00: cd cc 8c 3f cd cc 4c 3e 00 00 48 43 00 00 c8 42  | ...?..L>..HC...B
    0x10: 9a 99 59 3f 00 00 a0 40 00 00 70 42 00 00 48 43  | ..Y?...@..pB..HC
```

### 7. Complex Stateful Orchestration & Struct Building (Time Conversion Pipeline)
To prove full end-to-end capabilities, we can allocate space for a POSIX time structure (`struct tm`), populate a raw time buffer, convert it, and format it as a formatted string—all in a single shell run:
```bash
./oscall libc.so \
  alloc:t:8 :: \
  set:t:0:i64:1786270455 :: \
  alloc:tm:64 :: \
  localtime_r p:t p:tm :: \
  dump:tm:40 :: \
  alloc:out:64 :: \
  strftime p:out 64 s:%Y-%m-%d_%H:%M:%S p:tm :: \
  dump:out:32
```
**Output:**
```text
[!] === Executing Step 4 (localtime_r) ===
[+] Symbol Offset: 0x00000000000e7ad0
[!] Calling function with 2 args...
[+] Return (Hex): 0x0000007719166d20

[!] === Executing Step 5 (dump:tm:40) ===
[+] Pseudo-step: Hex/ASCII dump of `tm` (40 bytes):
    0x00: 0f 00 00 00 2c 00 00 00 0d 00 00 00 09 00 00 00  | ....,...........
    0x10: 07 00 00 00 7e 00 00 00 00 00 00 00 dc 00 00 00  | ....~...........
    0x20: 00 00 00 00 00 00 00 00                          | ........

[!] === Executing Step 7 (strftime) ===
[!] Calling function with 4 args...
[+] Return (Hex): 0x0000000000000013

[!] === Executing Step 8 (dump:out:32) ===
[+] Pseudo-step: Hex/ASCII dump of `out` (32 bytes):
    0x00: 32 30 32 36 2d 30 38 2d 30 39 5f 31 33 3a 34 34  | 2026-08-09_13:44
    0x10: 3a 31 35 00 00 00 00 00 00 00 00 00 00 00 00 00  | :15.............
```

---

## License
![License](https://img.shields.io/badge/License-EUPL1.2-red.svg)
