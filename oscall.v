module main

import os
import strconv

#flag -ldl
#include <dlfcn.h>

fn C.dlopen(filename &char, flags int) voidptr
fn C.dlsym(handle voidptr, symbol &char) voidptr
fn C.dlclose(handle voidptr) int
fn C.memcpy(dest voidptr, src voidptr, n int) voidptr
fn C.free(ptr voidptr)

struct Elf64_Ehdr {
	e_ident     [16]u8
	e_type      u16
	e_machine   u16
	e_version   u32
	e_entry     u64
	e_phoff     u64
	e_shoff     u64
	e_flags     u32
	e_ehsize    u16
	e_phentsize u16
	e_phnum     u16
	e_shentsize u16
	e_shnum     u16
	e_shstrndx  u16
}

struct Elf64_Shdr {
	sh_name      u32
	sh_type      u32
	sh_flags     u64
	sh_addr      u64
	sh_offset    u64
	sh_size      u64
	sh_link      u32
	sh_info      u32
	sh_addralign u64
	sh_entsize   u64
}

struct Elf64_Sym {
	st_name  u32
	st_info  u8
	st_other u8
	st_shndx u16
	st_value u64
	st_size  u64
}

fn find_elf_symbol_offset(file_path string, symbol_name string) u64 {
	mut file := os.open(file_path) or { return 0 }
	defer { file.close() }

	mut ehdr := Elf64_Ehdr{}
	ehdr_bytes := file.read_bytes_at(int(sizeof(Elf64_Ehdr)), 0)
	if ehdr_bytes.len < int(sizeof(Elf64_Ehdr)) { return 0 }
	unsafe {
		C.memcpy(&ehdr, ehdr_bytes.data, int(sizeof(Elf64_Ehdr)))
	}

	sh_num := ehdr.e_shnum
	sh_entsize := ehdr.e_shentsize
	shdrs_bytes := file.read_bytes_at(int(sh_num * sh_entsize), ehdr.e_shoff)
	if shdrs_bytes.len < int(sh_num * sh_entsize) { return 0 }

	mut shdrs := []Elf64_Shdr{len: int(sh_num)}
	unsafe {
		C.memcpy(shdrs.data, shdrs_bytes.data, int(sh_num * sh_entsize))
	}

	mut sym_shdr_idx := -1
	mut str_shdr_idx := -1

	for i, shdr in shdrs {
		if shdr.sh_type == 2 {
			sym_shdr_idx = i
			str_shdr_idx = int(shdr.sh_link)
			break
		}
	}

	if sym_shdr_idx == -1 {
		for i, shdr in shdrs {
			if shdr.sh_type == 11 {
				sym_shdr_idx = i
				str_shdr_idx = int(shdr.sh_link)
				break
			}
		}
	}

	if sym_shdr_idx == -1 || str_shdr_idx == -1 {
		return 0
	}

	sym_shdr := shdrs[sym_shdr_idx]
	str_shdr := shdrs[str_shdr_idx]

	sym_count := sym_shdr.sh_size / sym_shdr.sh_entsize
	syms_bytes := file.read_bytes_at(int(sym_shdr.sh_size), sym_shdr.sh_offset)
	if syms_bytes.len < int(sym_shdr.sh_size) { return 0 }

	mut syms := []Elf64_Sym{len: int(sym_count)}
	unsafe {
		C.memcpy(syms.data, syms_bytes.data, int(sym_shdr.sh_size))
	}

	strtab := file.read_bytes_at(int(str_shdr.sh_size), str_shdr.sh_offset)
	if strtab.len < int(str_shdr.sh_size) { return 0 }

	for sym in syms {
		if sym.st_name > 0 && sym.st_name < u32(strtab.len) {
			unsafe {
				name_ptr := &char(strtab.data) + sym.st_name
				name := name_ptr.vstring()
				if name == symbol_name {
					return sym.st_value
				}
			}
		}
	}

	for sym in syms {
		if sym.st_name > 0 && sym.st_name < u32(strtab.len) {
			unsafe {
				name_ptr := &char(strtab.data) + sym.st_name
				name := name_ptr.vstring()
				if name.contains(symbol_name) {
					return sym.st_value
				}
			}
		}
	}

	return 0
}

fn list_elf_symbols(file_path string) {
	mut file := os.open(file_path) or { return }
	defer { file.close() }

	mut ehdr := Elf64_Ehdr{}
	ehdr_bytes := file.read_bytes_at(int(sizeof(Elf64_Ehdr)), 0)
	if ehdr_bytes.len < int(sizeof(Elf64_Ehdr)) { return }
	unsafe {
		C.memcpy(&ehdr, ehdr_bytes.data, int(sizeof(Elf64_Ehdr)))
	}

	sh_num := ehdr.e_shnum
	sh_entsize := ehdr.e_shentsize
	shdrs_bytes := file.read_bytes_at(int(sh_num * sh_entsize), ehdr.e_shoff)
	if shdrs_bytes.len < int(sh_num * sh_entsize) { return }

	mut shdrs := []Elf64_Shdr{len: int(sh_num)}
	unsafe {
		C.memcpy(shdrs.data, shdrs_bytes.data, int(sh_num * sh_entsize))
	}

	mut sym_shdr_idx := -1
	mut str_shdr_idx := -1

	for i, shdr in shdrs {
		if shdr.sh_type == 2 {
			sym_shdr_idx = i
			str_shdr_idx = int(shdr.sh_link)
			break
		}
	}

	if sym_shdr_idx == -1 {
		for i, shdr in shdrs {
			if shdr.sh_type == 11 {
				sym_shdr_idx = i
				str_shdr_idx = int(shdr.sh_link)
				break
			}
		}
	}

	if sym_shdr_idx == -1 || str_shdr_idx == -1 {
		println("[-] Error: No symbol table found in ELF.")
		return
	}

	sym_shdr := shdrs[sym_shdr_idx]
	str_shdr := shdrs[str_shdr_idx]

	sym_count := sym_shdr.sh_size / sym_shdr.sh_entsize
	syms_bytes := file.read_bytes_at(int(sym_shdr.sh_size), sym_shdr.sh_offset)
	if syms_bytes.len < int(sym_shdr.sh_size) { return }

	mut syms := []Elf64_Sym{len: int(sym_count)}
	unsafe {
		C.memcpy(syms.data, syms_bytes.data, int(sym_shdr.sh_size))
	}

	strtab := file.read_bytes_at(int(str_shdr.sh_size), str_shdr.sh_offset)
	if strtab.len < int(str_shdr.sh_size) { return }

	println("[+] Total symbols found: " + sym_count.str())
	for sym in syms {
		if sym.st_name > 0 && sym.st_name < u32(strtab.len) {
			unsafe {
				name_ptr := &char(strtab.data) + sym.st_name
				name := name_ptr.vstring()
				println("  0x" + sym.st_value.hex_full() + " : " + name)
			}
		}
	}
}

fn get_base_address(lib_name string) u64 {
	lines := os.read_lines("/proc/self/maps") or { return 0 }
	for line in lines {
		if line.contains(lib_name) {
			parts := line.split("-")
			if parts.len > 0 {
				return strconv.parse_uint(parts[0], 16, 64) or { 0 }
			}
		}
	}
	return 0
}

type Call0 = fn () voidptr
type Call1 = fn (voidptr) voidptr
type Call2 = fn (voidptr, voidptr) voidptr
type Call3 = fn (voidptr, voidptr, voidptr) voidptr
type Call4 = fn (voidptr, voidptr, voidptr, voidptr) voidptr
type Call5 = fn (voidptr, voidptr, voidptr, voidptr, voidptr) voidptr
type Call6 = fn (voidptr, voidptr, voidptr, voidptr, voidptr, voidptr) voidptr
type Call7 = fn (voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr) voidptr
type Call8 = fn (voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr) voidptr
type Call9 = fn (voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr) voidptr
type Call10 = fn (voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr) voidptr
type Call11 = fn (voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr) voidptr
type Call12 = fn (voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr) voidptr

fn main() {
	if os.args.len < 3 {
		println("Usage:")
		println("  " + os.args[0] + " <lib_name_or_path> <symbol_name_or_substring> [arg1] [arg2] [arg3]...")
		println("  " + os.args[0] + " <lib_name_or_path> --list")
		println("Arg prefixes:")
		println("  123      -> Raw integer")
		println("  s:text   -> Pointer to null-terminated C-string")
		println("  p:0x123  -> Hex pointer address")
		println("  o:int    -> Allocate local int buffer, print output")
		println("  o:string -> Allocate local 512-byte string buffer, print output")
		return
	}

	mut lib_arg := os.args[1]
	sym_arg := os.args[2]

	mut lib_path := lib_arg
	if !lib_path.starts_with("/") {
		lib_path = "/system/lib64/" + lib_arg
		if !os.exists(lib_path) {
			lib_path = "/system/lib/" + lib_arg
		}
		if !os.exists(lib_path) {
			lib_path = "/vendor/lib64/" + lib_arg
		}
		if !os.exists(lib_path) {
			lib_path = "/vendor/lib/" + lib_arg
		}
	}

	if !os.exists(lib_path) {
		println("[-] Error: Library not found at: " + lib_path)
		return
	}

	if sym_arg == "--list" || sym_arg == "-l" {
		list_elf_symbols(lib_path)
		return
	}

	handle := C.dlopen(&char(lib_path.str), 1)
	if isnil(handle) {
		println("[-] Error: Failed to load library " + lib_path)
		return
	}

	base_addr := get_base_address(os.file_name(lib_path))
	if base_addr == 0 {
		println("[-] Error: Base address not found.")
		C.dlclose(handle)
		return
	}

	offset := find_elf_symbol_offset(lib_path, sym_arg)

	if offset == 0 {
		println("[-] Symbol not found in ELF headers.")
		C.dlclose(handle)
		return
	}

	println("[+] Library Base Address: 0x" + base_addr.hex_full())
	println("[+] Symbol Offset: 0x" + offset.hex_full())

	target_addr := voidptr(base_addr + offset)
	println("[+] Target Memory Address: " + target_addr.str())

	mut args := []voidptr{}
	mut out_buffers := []voidptr{}
	mut out_types := []string{}
	mut out_indices := []int{}

	for i := 3; i < os.args.len; i++ {
		arg_str := os.args[i]
		if arg_str.starts_with("s:") {
			val_str := arg_str.substr(2, arg_str.len)
			args << voidptr(val_str.str)
		} else if arg_str.starts_with("p:") {
			val_str := arg_str.substr(2, arg_str.len)
			hex_val := strconv.parse_uint(val_str.replace("0x", ""), 16, 64) or { 0 }
			args << voidptr(hex_val)
		} else if arg_str == "o:int" {
			unsafe {
				mut local_buf := &int(malloc(int(sizeof(int))))
				*local_buf = 0
				args << voidptr(local_buf)
				out_buffers << voidptr(local_buf)
				out_types << "int"
				out_indices << (i - 3)
			}
		} else if arg_str == "o:string" {
			unsafe {
				mut local_buf := malloc(512)
				*&u8(local_buf) = 0
				args << voidptr(local_buf)
				out_buffers << voidptr(local_buf)
				out_types << "string"
				out_indices << (i - 3)
			}
		} else {
			args << voidptr(arg_str.int())
		}
	}

	println("[!] Executing function call...")
	unsafe {
		match args.len {
			0 {
				func := Call0(target_addr)
				res := func()
				println("[+] Execution finished. Return Code: 0x" + u64(res).hex_full())
			}
			1 {
				func := Call1(target_addr)
				res := func(args[0])
				println("[+] Execution finished. Return Code: 0x" + u64(res).hex_full())
			}
			2 {
				func := Call2(target_addr)
				res := func(args[0], args[1])
				println("[+] Execution finished. Return Code: 0x" + u64(res).hex_full())
			}
			3 {
				func := Call3(target_addr)
				res := func(args[0], args[1], args[2])
				println("[+] Execution finished. Return Code: 0x" + u64(res).hex_full())
			}
			4 {
				func := Call4(target_addr)
				res := func(args[0], args[1], args[2], args[3])
				println("[+] Execution finished. Return Code: 0x" + u64(res).hex_full())
			}
			5 {
				func := Call5(target_addr)
				res := func(args[0], args[1], args[2], args[3], args[4])
				println("[+] Execution finished. Return Code: 0x" + u64(res).hex_full())
			}
			6 {
				func := Call6(target_addr)
				res := func(args[0], args[1], args[2], args[3], args[4], args[5])
				println("[+] Execution finished. Return Code: 0x" + u64(res).hex_full())
			}
			7 {
				func := Call7(target_addr)
				res := func(args[0], args[1], args[2], args[3], args[4], args[5], args[6])
				println("[+] Execution finished. Return Code: 0x" + u64(res).hex_full())
			}
			8 {
				func := Call8(target_addr)
				res := func(args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7])
				println("[+] Execution finished. Return Code: 0x" + u64(res).hex_full())
			}
			9 {
				func := Call9(target_addr)
				res := func(args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8])
				println("[+] Execution finished. Return Code: 0x" + u64(res).hex_full())
			}
			10 {
				func := Call10(target_addr)
				res := func(args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8], args[9])
				println("[+] Execution finished. Return Code: 0x" + u64(res).hex_full())
			}
			11 {
				func := Call11(target_addr)
				res := func(args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8], args[9], args[10])
				println("[+] Execution finished. Return Code: 0x" + u64(res).hex_full())
			}
			12 {
				func := Call12(target_addr)
				res := func(args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8], args[9], args[10], args[11])
				println("[+] Execution finished. Return Code: 0x" + u64(res).hex_full())
			}
			else {
				println("[-] Error: Unsupported number of arguments.")
			}
		}
	}

	for idx, buf in out_buffers {
		unsafe {
			if out_types[idx] == "int" {
				println("[+] Output buffer at Argument #" + out_indices[idx].str() + " updated to: " + (*&int(buf)).str())
			} else if out_types[idx] == "string" {
				println("[+] Output buffer at Argument #" + out_indices[idx].str() + " updated to: " + (&char(buf)).vstring())
			}
		}
	}

	C.dlclose(handle)
}
