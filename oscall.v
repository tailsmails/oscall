module main

import os
import strconv
import time

#flag -ldl
#include <dlfcn.h>
#include "helper.h"

fn C.dlopen(filename &char, flags int) voidptr
fn C.dlsym(handle voidptr, symbol &char) voidptr
fn C.dlclose(handle voidptr) int
fn C.memcpy(dest voidptr, src voidptr, n usize) voidptr
fn C.memset(dest voidptr, val int, n usize) voidptr
fn C.free(ptr voidptr)
fn C.signal(sig int, handler voidptr) voidptr
fn C.v_segfault_handler(sig int)
fn C.safe_sigsetjmp() int

fn C.get_remote_module_base(pid int, module_name &char) u64
fn C.remote_call_arch(pid int, func_addr u64, argc int, argv &u64) u64
fn C.write_remote_mem(pid int, dst u64, src voidptr, len usize) int
fn C.read_remote_mem(pid int, dst voidptr, src u64, len usize) int

struct LocalBuffer {
	ptr  voidptr
	size int
}

struct Elf32_Ehdr {
	e_ident     [16]u8
	e_type      u16
	e_machine   u16
	e_version   u32
	e_entry     u32
	e_phoff     u32
	e_shoff     u32
	e_flags     u32
	e_ehsize    u16
	e_phentsize u16
	e_phnum     u16
	e_shentsize u16
	e_shnum     u16
	e_shstrndx  u16
}

struct Elf32_Shdr {
	sh_name      u32
	sh_type      u32
	sh_flags     u32
	sh_addr      u32
	sh_offset    u32
	sh_size      u32
	sh_link      u32
	sh_info      u32
	sh_addralign u32
	sh_entsize   u32
}

struct Elf32_Sym {
	st_name  u32
	st_value u32
	st_size  u32
	st_info  u8
	st_other u8
	st_shndx u16
}

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

struct Elf64_Dyn {
	d_tag i64
	d_val u64
}

struct Elf32_Dyn {
	d_tag i32
	d_val u32
}

fn get_elf_soname(file_path string) string {
	if !os.exists(file_path) { return "" }
	file_size := os.file_size(file_path)
	if file_size < 52 { return "" }

	mut file := os.open(file_path) or { return "" }
	defer { file.close() }

	ident := file.read_bytes_at(16, 0)
	if ident.len < 16 { return "" }
	if ident[0] != 0x7f || ident[1] != `E` || ident[2] != `L` || ident[3] != `F` {
		return ""
	}
	class := ident[4]
	if class != 1 && class != 2 { return "" }

	if class == 2 {
		if file_size < i64(sizeof(Elf64_Ehdr)) { return "" }
		mut ehdr := Elf64_Ehdr{}
		ehdr_bytes := file.read_bytes_at(int(sizeof(Elf64_Ehdr)), 0)
		if ehdr_bytes.len < int(sizeof(Elf64_Ehdr)) { return "" }
		unsafe {
			C.memcpy(&ehdr, ehdr_bytes.data, sizeof(Elf64_Ehdr))
		}

		sh_num := ehdr.e_shnum
		sh_entsize := ehdr.e_shentsize
		if sh_entsize < sizeof(Elf64_Shdr) || sh_num == 0 || sh_num > 10000 {
			return ""
		}
		shdrs_bytes := file.read_bytes_at(int(sh_num * sh_entsize), ehdr.e_shoff)
		if shdrs_bytes.len < int(sh_num * sh_entsize) { return "" }

		mut shdrs := []Elf64_Shdr{len: int(sh_num)}
		unsafe {
			C.memcpy(shdrs.data, shdrs_bytes.data, usize(sh_num * sh_entsize))
		}

		mut dyn_shdr_idx := -1
		mut dynstr_shdr_idx := -1

		for i, shdr in shdrs {
			if shdr.sh_type == 6 {
				dyn_shdr_idx = i
				dynstr_shdr_idx = int(shdr.sh_link)
				break
			}
		}

		if dyn_shdr_idx == -1 || dynstr_shdr_idx == -1 {
			return ""
		}

		dyn_shdr := shdrs[dyn_shdr_idx]
		dynstr_shdr := shdrs[dynstr_shdr_idx]

		dyn_entry_count := dyn_shdr.sh_size / sizeof(Elf64_Dyn)
		if dyn_entry_count == 0 || dyn_entry_count > 10000 { return "" }

		dyn_bytes := file.read_bytes_at(int(dyn_shdr.sh_size), dyn_shdr.sh_offset)
		if dyn_bytes.len < int(dyn_shdr.sh_size) { return "" }

		mut dyn_entries := []Elf64_Dyn{len: int(dyn_entry_count)}
		unsafe {
			C.memcpy(dyn_entries.data, dyn_bytes.data, usize(dyn_shdr.sh_size))
		}

		dynstr := file.read_bytes_at(int(dynstr_shdr.sh_size), dynstr_shdr.sh_offset)
		if dynstr.len < int(dynstr_shdr.sh_size) { return "" }

		for entry in dyn_entries {
			if entry.d_tag == 14 {
				offset := entry.d_val
				if offset < u64(dynstr.len) {
					mut end := int(offset)
					for end < dynstr.len && dynstr[end] != 0 {
						end++
					}
					return dynstr[int(offset)..end].bytestr()
				}
			}
		}
	} else {
		if file_size < i64(sizeof(Elf32_Ehdr)) { return "" }
		mut ehdr := Elf32_Ehdr{}
		ehdr_bytes := file.read_bytes_at(int(sizeof(Elf32_Ehdr)), 0)
		if ehdr_bytes.len < int(sizeof(Elf32_Ehdr)) { return "" }
		unsafe {
			C.memcpy(&ehdr, ehdr_bytes.data, sizeof(Elf32_Ehdr))
		}

		sh_num := ehdr.e_shnum
		sh_entsize := ehdr.e_shentsize
		if sh_entsize < sizeof(Elf32_Shdr) || sh_num == 0 || sh_num > 10000 {
			return ""
		}
		shdrs_bytes := file.read_bytes_at(int(sh_num * sh_entsize), ehdr.e_shoff)
		if shdrs_bytes.len < int(sh_num * sh_entsize) { return "" }

		mut shdrs := []Elf32_Shdr{len: int(sh_num)}
		unsafe {
			C.memcpy(shdrs.data, shdrs_bytes.data, usize(sh_num * sh_entsize))
		}

		mut dyn_shdr_idx := -1
		mut dynstr_shdr_idx := -1

		for i, shdr in shdrs {
			if shdr.sh_type == 6 {
				dyn_shdr_idx = i
				dynstr_shdr_idx = int(shdr.sh_link)
				break
			}
		}

		if dyn_shdr_idx == -1 || dynstr_shdr_idx == -1 {
			return ""
		}

		dyn_shdr := shdrs[dyn_shdr_idx]
		dynstr_shdr := shdrs[dynstr_shdr_idx]

		dyn_entry_count := dyn_shdr.sh_size / sizeof(Elf32_Dyn)
		if dyn_entry_count == 0 || dyn_entry_count > 10000 { return "" }

		dyn_bytes := file.read_bytes_at(int(dyn_shdr.sh_size), dyn_shdr.sh_offset)
		if dyn_bytes.len < int(dyn_shdr.sh_size) { return "" }

		mut dyn_entries := []Elf32_Dyn{len: int(dyn_entry_count)}
		unsafe {
			C.memcpy(dyn_entries.data, dyn_bytes.data, usize(dyn_shdr.sh_size))
		}

		dynstr := file.read_bytes_at(int(dynstr_shdr.sh_size), dynstr_shdr.sh_offset)
		if dynstr.len < int(dynstr_shdr.sh_size) { return "" }

		for entry in dyn_entries {
			if entry.d_tag == 14 {
				offset := entry.d_val
				if offset < u32(dynstr.len) {
					mut end := int(offset)
					for end < dynstr.len && dynstr[end] != 0 {
						end++
					}
					return dynstr[int(offset)..end].bytestr()
				}
			}
		}
	}
	return ""
}

fn resolve_dependency_path(name string, base_dir string) string {
	target_path := os.join_path(base_dir, name)
	if os.exists(target_path) { return target_path }
	std_paths := [
		"/system/lib64/" + name,
		"/vendor/lib64/" + name,
		"/system_ext/lib64/" + name,
		"/odm/lib64/" + name,
		"/product/lib64/" + name,
		"/vendor/lib64/hw/" + name,
		"/system/lib64/hw/" + name,
		"/system/lib/" + name,
		"/vendor/lib/" + name,
		"/system_ext/lib/" + name,
		"/odm/lib/" + name,
		"/product/lib/" + name,
		"/vendor/lib/hw/" + name,
		"/system/lib/hw/" + name,
	]
	for p in std_paths {
		if os.exists(p) { return p }
	}

	dir_files := os.ls(base_dir) or { []string{} }
	for f in dir_files {
		if f.ends_with(".so") {
			full_p := os.join_path(base_dir, f)
			if get_elf_soname(full_p) == name {
				return full_p
			}
		}
	}

	fallback_dirs := [
		"/system/lib64/",
		"/vendor/lib64/",
		"/system_ext/lib64/",
		"/odm/lib64/",
		"/product/lib64/",
		"/system/lib/",
		"/vendor/lib/",
	]
	for d in fallback_dirs {
		if d == base_dir { continue }
		if !os.exists(d) { continue }
		files_in_d := os.ls(d) or { []string{} }
		for f in files_in_d {
			if f.ends_with(".so") {
				full_p := os.join_path(d, f)
				if get_elf_soname(full_p) == name {
					return full_p
				}
			}
		}
	}
	return ""
}

fn get_elf_dependencies(file_path string) []string {
	mut deps := []string{}
	if !os.exists(file_path) { return deps }
	file_size := os.file_size(file_path)
	if file_size < 52 { return deps }

	mut file := os.open(file_path) or { return deps }
	defer { file.close() }

	ident := file.read_bytes_at(16, 0)
	if ident.len < 16 { return deps }
	if ident[0] != 0x7f || ident[1] != `E` || ident[2] != `L` || ident[3] != `F` {
		return deps
	}
	class := ident[4]
	if class != 1 && class != 2 { return deps }

	if class == 2 {
		if file_size < i64(sizeof(Elf64_Ehdr)) { return deps }
		mut ehdr := Elf64_Ehdr{}
		ehdr_bytes := file.read_bytes_at(int(sizeof(Elf64_Ehdr)), 0)
		if ehdr_bytes.len < int(sizeof(Elf64_Ehdr)) { return deps }
		unsafe {
			C.memcpy(&ehdr, ehdr_bytes.data, sizeof(Elf64_Ehdr))
		}

		sh_num := ehdr.e_shnum
		sh_entsize := ehdr.e_shentsize
		if sh_entsize < sizeof(Elf64_Shdr) || sh_num == 0 || sh_num > 10000 {
			return deps
		}
		shdrs_bytes := file.read_bytes_at(int(sh_num * sh_entsize), ehdr.e_shoff)
		if shdrs_bytes.len < int(sh_num * sh_entsize) { return deps }

		mut shdrs := []Elf64_Shdr{len: int(sh_num)}
		unsafe {
			C.memcpy(shdrs.data, shdrs_bytes.data, usize(sh_num * sh_entsize))
		}

		mut dyn_shdr_idx := -1
		mut dynstr_shdr_idx := -1

		for i, shdr in shdrs {
			if shdr.sh_type == 6 {
				dyn_shdr_idx = i
				dynstr_shdr_idx = int(shdr.sh_link)
				break
			}
		}

		if dyn_shdr_idx == -1 || dynstr_shdr_idx == -1 {
			return deps
		}

		dyn_shdr := shdrs[dyn_shdr_idx]
		dynstr_shdr := shdrs[dynstr_shdr_idx]

		dyn_entry_count := dyn_shdr.sh_size / sizeof(Elf64_Dyn)
		if dyn_entry_count == 0 || dyn_entry_count > 10000 { return deps }

		dyn_bytes := file.read_bytes_at(int(dyn_shdr.sh_size), dyn_shdr.sh_offset)
		if dyn_bytes.len < int(dyn_shdr.sh_size) { return deps }

		mut dyn_entries := []Elf64_Dyn{len: int(dyn_entry_count)}
		unsafe {
			C.memcpy(dyn_entries.data, dyn_bytes.data, usize(dyn_shdr.sh_size))
		}

		dynstr := file.read_bytes_at(int(dynstr_shdr.sh_size), dynstr_shdr.sh_offset)
		if dynstr.len < int(dynstr_shdr.sh_size) { return deps }

		for entry in dyn_entries {
			if entry.d_tag == 1 {
				offset := entry.d_val
				if offset < u64(dynstr.len) {
					mut end := int(offset)
					for end < dynstr.len && dynstr[end] != 0 {
						end++
					}
					dep_name := dynstr[int(offset)..end].bytestr()
					if dep_name.len > 0 {
						deps << dep_name
					}
				}
			}
		}
	} else {
		if file_size < i64(sizeof(Elf32_Ehdr)) { return deps }
		mut ehdr := Elf32_Ehdr{}
		ehdr_bytes := file.read_bytes_at(int(sizeof(Elf32_Ehdr)), 0)
		if ehdr_bytes.len < int(sizeof(Elf32_Ehdr)) { return deps }
		unsafe {
			C.memcpy(&ehdr, ehdr_bytes.data, sizeof(Elf32_Ehdr))
		}

		sh_num := ehdr.e_shnum
		sh_entsize := ehdr.e_shentsize
		if sh_entsize < sizeof(Elf32_Shdr) || sh_num == 0 || sh_num > 10000 {
			return deps
		}
		shdrs_bytes := file.read_bytes_at(int(sh_num * sh_entsize), ehdr.e_shoff)
		if shdrs_bytes.len < int(sh_num * sh_entsize) { return deps }

		mut shdrs := []Elf32_Shdr{len: int(sh_num)}
		unsafe {
			C.memcpy(shdrs.data, shdrs_bytes.data, usize(sh_num * sh_entsize))
		}

		mut dyn_shdr_idx := -1
		mut dynstr_shdr_idx := -1

		for i, shdr in shdrs {
			if shdr.sh_type == 6 {
				dyn_shdr_idx = i
				dynstr_shdr_idx = int(shdr.sh_link)
				break
			}
		}

		if dyn_shdr_idx == -1 || dynstr_shdr_idx == -1 {
			return deps
		}

		dyn_shdr := shdrs[dyn_shdr_idx]
		dynstr_shdr := shdrs[dynstr_shdr_idx]

		dyn_entry_count := dyn_shdr.sh_size / sizeof(Elf32_Dyn)
		if dyn_entry_count == 0 || dyn_entry_count > 10000 { return deps }

		dyn_bytes := file.read_bytes_at(int(dyn_shdr.sh_size), dyn_shdr.sh_offset)
		if dyn_bytes.len < int(dyn_shdr.sh_size) { return deps }

		mut dyn_entries := []Elf32_Dyn{len: int(dyn_entry_count)}
		unsafe {
			C.memcpy(dyn_entries.data, dyn_bytes.data, usize(dyn_shdr.sh_size))
		}

		dynstr := file.read_bytes_at(int(dynstr_shdr.sh_size), dynstr_shdr.sh_offset)
		if dynstr.len < int(dynstr_shdr.sh_size) { return deps }

		for entry in dyn_entries {
			if entry.d_tag == 1 {
				offset := entry.d_val
				if offset < u32(dynstr.len) {
					mut end := int(offset)
					for end < dynstr.len && dynstr[end] != 0 {
						end++
					}
					dep_name := dynstr[int(offset)..end].bytestr()
					if dep_name.len > 0 {
						deps << dep_name
					}
				}
			}
		}
	}
	return deps
}

fn load_dependencies_recursive(lib_path string, mut loaded_map map[string]bool) {
	base_dir := os.dir(lib_path)
	deps := get_elf_dependencies(lib_path)
	for dep in deps {
		if dep in ["libc.so", "libm.so", "libdl.so", "liblog.so"] { continue }
		if dep in loaded_map { continue }
		dep_path := resolve_dependency_path(dep, base_dir)
		if dep_path.len > 0 {
			load_dependencies_recursive(dep_path, mut loaded_map)
			dep_handle := C.dlopen(&char(dep_path.str), 2 | 0x100)
			if isnil(dep_handle) {
				println("  [-] Warning: Failed to pre-load dependency: " + dep)
			} else {
				loaded_map[dep] = true
				println("  -> Found dependency: " + dep_path + " (Pre-loaded)")
			}
		} else {
			println("  [-] Warning: Could not resolve path for dependency: " + dep)
		}
	}
}

fn find_elf_symbol_offset(file_path string, symbol_name string) u64 {
	if !os.exists(file_path) { return 0 }
	file_size := os.file_size(file_path)
	if file_size < 52 { return 0 }

	mut file := os.open(file_path) or { return 0 }
	defer { file.close() }

	ident := file.read_bytes_at(16, 0)
	if ident.len < 16 { return 0 }
	if ident[0] != 0x7f || ident[1] != `E` || ident[2] != `L` || ident[3] != `F` {
		return 0
	}
	class := ident[4]
	if class != 1 && class != 2 { return 0 }

	if class == 2 {
		if file_size < i64(sizeof(Elf64_Ehdr)) { return 0 }
		mut ehdr := Elf64_Ehdr{}
		ehdr_bytes := file.read_bytes_at(int(sizeof(Elf64_Ehdr)), 0)
		if ehdr_bytes.len < int(sizeof(Elf64_Ehdr)) { return 0 }
		unsafe {
			C.memcpy(&ehdr, ehdr_bytes.data, sizeof(Elf64_Ehdr))
		}

		sh_num := ehdr.e_shnum
		sh_entsize := ehdr.e_shentsize
		if sh_entsize < sizeof(Elf64_Shdr) || sh_num == 0 || sh_num > 10000 {
			return 0
		}
		if ehdr.e_shoff >= u64(file_size) || u64(sh_num) * u64(sh_entsize) > u64(file_size) - ehdr.e_shoff {
			return 0
		}

		shdrs_bytes := file.read_bytes_at(int(sh_num * sh_entsize), ehdr.e_shoff)
		if shdrs_bytes.len < int(sh_num * sh_entsize) { return 0 }

		mut shdrs := []Elf64_Shdr{len: int(sh_num)}
		unsafe {
			C.memcpy(shdrs.data, shdrs_bytes.data, usize(sh_num * sh_entsize))
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
		if sym_shdr_idx >= shdrs.len || str_shdr_idx >= shdrs.len {
			return 0
		}

		sym_shdr := shdrs[sym_shdr_idx]
		str_shdr := shdrs[str_shdr_idx]

		if sym_shdr.sh_entsize < sizeof(Elf64_Sym) || sym_shdr.sh_entsize == 0 {
			return 0
		}
		if sym_shdr.sh_offset >= u64(file_size) || sym_shdr.sh_size > u64(file_size) - sym_shdr.sh_offset {
			return 0
		}
		if str_shdr.sh_offset >= u64(file_size) || str_shdr.sh_size > u64(file_size) - str_shdr.sh_offset {
			return 0
		}

		sym_count := sym_shdr.sh_size / sym_shdr.sh_entsize
		if sym_count == 0 || sym_count > 1000000 {
			return 0
		}

		syms_bytes := file.read_bytes_at(int(sym_shdr.sh_size), sym_shdr.sh_offset)
		if syms_bytes.len < int(sym_shdr.sh_size) { return 0 }

		mut syms := []Elf64_Sym{len: int(sym_count)}
		unsafe {
			C.memcpy(syms.data, syms_bytes.data, usize(sym_shdr.sh_size))
		}

		strtab := file.read_bytes_at(int(str_shdr.sh_size), str_shdr.sh_offset)
		if strtab.len < int(str_shdr.sh_size) { return 0 }

		for sym in syms {
			if sym.st_name > 0 && sym.st_name < u32(strtab.len) {
				mut end := int(sym.st_name)
				for end < strtab.len && strtab[end] != 0 {
					end++
				}
				name := strtab[int(sym.st_name)..end].bytestr()
				if name == symbol_name {
					return sym.st_value
				}
			}
		}

		for sym in syms {
			if sym.st_name > 0 && sym.st_name < u32(strtab.len) {
				mut end := int(sym.st_name)
				for end < strtab.len && strtab[end] != 0 {
					end++
				}
				name := strtab[int(sym.st_name)..end].bytestr()
				if name.contains(symbol_name) {
					return sym.st_value
				}
			}
		}
	} else {
		if file_size < i64(sizeof(Elf32_Ehdr)) { return 0 }
		mut ehdr := Elf32_Ehdr{}
		ehdr_bytes := file.read_bytes_at(int(sizeof(Elf32_Ehdr)), 0)
		if ehdr_bytes.len < int(sizeof(Elf32_Ehdr)) { return 0 }
		unsafe {
			C.memcpy(&ehdr, ehdr_bytes.data, sizeof(Elf32_Ehdr))
		}

		sh_num := ehdr.e_shnum
		sh_entsize := ehdr.e_shentsize
		if sh_entsize < sizeof(Elf32_Shdr) || sh_num == 0 || sh_num > 10000 {
			return 0
		}
		if ehdr.e_shoff >= u32(file_size) || u32(sh_num) * u32(sh_entsize) > u32(file_size) - ehdr.e_shoff {
			return 0
		}

		shdrs_bytes := file.read_bytes_at(int(sh_num * sh_entsize), ehdr.e_shoff)
		if shdrs_bytes.len < int(sh_num * sh_entsize) { return 0 }

		mut shdrs := []Elf32_Shdr{len: int(sh_num)}
		unsafe {
			C.memcpy(shdrs.data, shdrs_bytes.data, usize(sh_num * sh_entsize))
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
		if sym_shdr_idx >= shdrs.len || str_shdr_idx >= shdrs.len {
			return 0
		}

		sym_shdr := shdrs[sym_shdr_idx]
		str_shdr := shdrs[str_shdr_idx]

		if sym_shdr.sh_entsize < sizeof(Elf32_Sym) || sym_shdr.sh_entsize == 0 {
			return 0
		}
		if sym_shdr.sh_offset >= u32(file_size) || sym_shdr.sh_size > u32(file_size) - sym_shdr.sh_offset {
			return 0
		}
		if str_shdr.sh_offset >= u32(file_size) || str_shdr.sh_size > u32(file_size) - str_shdr.sh_offset {
			return 0
		}

		sym_count := sym_shdr.sh_size / sym_shdr.sh_entsize
		if sym_count == 0 || sym_count > 1000000 {
			return 0
		}

		syms_bytes := file.read_bytes_at(int(sym_shdr.sh_size), sym_shdr.sh_offset)
		if syms_bytes.len < int(sym_shdr.sh_size) { return 0 }

		mut syms := []Elf32_Sym{len: int(sym_count)}
		unsafe {
			C.memcpy(syms.data, syms_bytes.data, usize(sym_shdr.sh_size))
		}

		strtab := file.read_bytes_at(int(str_shdr.sh_size), str_shdr.sh_offset)
		if strtab.len < int(str_shdr.sh_size) { return 0 }

		for sym in syms {
			if sym.st_name > 0 && sym.st_name < u32(strtab.len) {
				mut end := int(sym.st_name)
				for end < strtab.len && strtab[end] != 0 {
					end++
				}
				name := strtab[int(sym.st_name)..end].bytestr()
				if name == symbol_name {
					return u64(sym.st_value)
				}
			}
		}

		for sym in syms {
			if sym.st_name > 0 && sym.st_name < u32(strtab.len) {
				mut end := int(sym.st_name)
				for end < strtab.len && strtab[end] != 0 {
					end++
				}
				name := strtab[int(sym.st_name)..end].bytestr()
				if name.contains(symbol_name) {
					return u64(sym.st_value)
				}
			}
		}
	}

	return 0
}

fn list_elf_symbols(file_path string) {
	if !os.exists(file_path) { return }
	file_size := os.file_size(file_path)
	if file_size < 52 { return }

	mut file := os.open(file_path) or { return }
	defer { file.close() }

	ident := file.read_bytes_at(16, 0)
	if ident.len < 16 { return }
	if ident[0] != 0x7f || ident[1] != `E` || ident[2] != `L` || ident[3] != `F` {
		return
	}
	class := ident[4]
	if class != 1 && class != 2 { return }

	if class == 2 {
		if file_size < i64(sizeof(Elf64_Ehdr)) { return }
		mut ehdr := Elf64_Ehdr{}
		ehdr_bytes := file.read_bytes_at(int(sizeof(Elf64_Ehdr)), 0)
		if ehdr_bytes.len < int(sizeof(Elf64_Ehdr)) { return }
		unsafe {
			C.memcpy(&ehdr, ehdr_bytes.data, sizeof(Elf64_Ehdr))
		}

		sh_num := ehdr.e_shnum
		sh_entsize := ehdr.e_shentsize
		if sh_entsize < sizeof(Elf64_Shdr) || sh_num == 0 || sh_num > 10000 {
			return
		}
		if ehdr.e_shoff >= u64(file_size) || u64(sh_num) * u64(sh_entsize) > u64(file_size) - ehdr.e_shoff {
			return
		}

		shdrs_bytes := file.read_bytes_at(int(sh_num * sh_entsize), ehdr.e_shoff)
		if shdrs_bytes.len < int(sh_num * sh_entsize) { return }

		mut shdrs := []Elf64_Shdr{len: int(sh_num)}
		unsafe {
			C.memcpy(shdrs.data, shdrs_bytes.data, usize(sh_num * sh_entsize))
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
		if sym_shdr_idx >= shdrs.len || str_shdr_idx >= shdrs.len {
			println("[-] Error: Invalid section indices in ELF headers.")
			return
		}

		sym_shdr := shdrs[sym_shdr_idx]
		str_shdr := shdrs[str_shdr_idx]

		if sym_shdr.sh_entsize < sizeof(Elf64_Sym) || sym_shdr.sh_entsize == 0 {
			return
		}
		if sym_shdr.sh_offset >= u64(file_size) || sym_shdr.sh_size > u64(file_size) - sym_shdr.sh_offset {
			return
		}
		if str_shdr.sh_offset >= u64(file_size) || str_shdr.sh_size > u64(file_size) - str_shdr.sh_offset {
			return
		}

		sym_count := sym_shdr.sh_size / sym_shdr.sh_entsize
		if sym_count == 0 || sym_count > 1000000 {
			return
		}

		syms_bytes := file.read_bytes_at(int(sym_shdr.sh_size), sym_shdr.sh_offset)
		if syms_bytes.len < int(sym_shdr.sh_size) { return }

		mut syms := []Elf64_Sym{len: int(sym_count)}
		unsafe {
			C.memcpy(syms.data, syms_bytes.data, usize(sym_shdr.sh_size))
		}

		strtab := file.read_bytes_at(int(str_shdr.sh_size), str_shdr.sh_offset)
		if strtab.len < int(str_shdr.sh_size) { return }

		println("[+] Total symbols found: " + sym_count.str())
		for sym in syms {
			if sym.st_name > 0 && sym.st_name < u32(strtab.len) {
				mut end := int(sym.st_name)
				for end < strtab.len && strtab[end] != 0 {
					end++
				}
				name := strtab[int(sym.st_name)..end].bytestr()
				println("  0x" + sym.st_value.hex_full() + " : " + name)
			}
		}
	} else {
		if file_size < i64(sizeof(Elf32_Ehdr)) { return }
		mut ehdr := Elf32_Ehdr{}
		ehdr_bytes := file.read_bytes_at(int(sizeof(Elf32_Ehdr)), 0)
		if ehdr_bytes.len < int(sizeof(Elf32_Ehdr)) { return }
		unsafe {
			C.memcpy(&ehdr, ehdr_bytes.data, sizeof(Elf32_Ehdr))
		}

		sh_num := ehdr.e_shnum
		sh_entsize := ehdr.e_shentsize
		if sh_entsize < sizeof(Elf32_Shdr) || sh_num == 0 || sh_num > 10000 {
			return
		}
		if ehdr.e_shoff >= u32(file_size) || u32(sh_num) * u32(sh_entsize) > u32(file_size) - ehdr.e_shoff {
			return
		}

		shdrs_bytes := file.read_bytes_at(int(sh_num * sh_entsize), ehdr.e_shoff)
		if shdrs_bytes.len < int(sh_num * sh_entsize) { return }

		mut shdrs := []Elf32_Shdr{len: int(sh_num)}
		unsafe {
			C.memcpy(shdrs.data, shdrs_bytes.data, usize(sh_num * sh_entsize))
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
		if sym_shdr_idx >= shdrs.len || str_shdr_idx >= shdrs.len {
			println("[-] Error: Invalid section indices in ELF headers.")
			return
		}

		sym_shdr := shdrs[sym_shdr_idx]
		str_shdr := shdrs[str_shdr_idx]

		if sym_shdr.sh_entsize < sizeof(Elf32_Sym) || sym_shdr.sh_entsize == 0 {
			return
		}
		if sym_shdr.sh_offset >= u32(file_size) || sym_shdr.sh_size > u32(file_size) - sym_shdr.sh_offset {
			return
		}
		if str_shdr.sh_offset >= u32(file_size) || str_shdr.sh_size > u32(file_size) - str_shdr.sh_offset {
			return
		}

		sym_count := sym_shdr.sh_size / sym_shdr.sh_entsize
		if sym_count == 0 || sym_count > 1000000 {
			return
		}

		syms_bytes := file.read_bytes_at(int(sym_shdr.sh_size), sym_shdr.sh_offset)
		if syms_bytes.len < int(sym_shdr.sh_size) { return }

		mut syms := []Elf32_Sym{len: int(sym_count)}
		unsafe {
			C.memcpy(syms.data, syms_bytes.data, usize(sym_shdr.sh_size))
		}

		strtab := file.read_bytes_at(int(str_shdr.sh_size), str_shdr.sh_offset)
		if strtab.len < int(str_shdr.sh_size) { return }

		println("[+] Total symbols found: " + sym_count.str())
		for sym in syms {
			if sym.st_name > 0 && sym.st_name < u32(strtab.len) {
				mut end := int(sym.st_name)
				for end < strtab.len && strtab[end] != 0 {
					end++
				}
				name := strtab[int(sym.st_name)..end].bytestr()
				println("  0x" + sym.st_value.hex() + " : " + name)
			}
		}
	}
}

fn get_base_address(lib_name string) u64 {
	lines := os.read_lines("/proc/self/maps") or { return 0 }
	for line in lines {
		if line.contains(lib_name) {
			parts := line.split("-")
			if parts.len >= 2 {
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

fn main() {
	if os.args.len < 3 {
		println("Usage:")
		println("  [Local Mode]:  " + os.args[0] + " <lib_name_or_path> <symbol_name> [args...]")
		println("  [Remote Mode]: " + os.args[0] + " -p <pid> <lib_name_or_path> <symbol_name> [args...]")
		println("  [Chaining]:    " + os.args[0] + " <lib_name_or_path> <sym1> [args] :: <sym2> [args] :: ...")
		println("  [Symbol List]: " + os.args[0] + " <lib_name_or_path> --list")
		return
	}

	mut target_pid := 0
	mut start_arg_idx := 1

	if os.args[1] == "-p" || os.args[1] == "--pid" {
		target_pid = os.args[2].int()
		start_arg_idx = 3
	}

	mut lib_arg := os.args[start_arg_idx]
	mut lib_path := lib_arg
	if !lib_path.starts_with("/") {
		lib_path = "/system/lib64/" + lib_arg
		if !os.exists(lib_path) { lib_path = "/system/lib/" + lib_arg }
		if !os.exists(lib_path) { lib_path = "/vendor/lib64/" + lib_arg }
		if !os.exists(lib_path) { lib_path = "/vendor/lib/" + lib_arg }
	}

	if !os.exists(lib_path) {
		println("[-] Error: Library not found at: " + lib_path)
		return
	}

	if os.args[start_arg_idx + 1] == "--list" || os.args[start_arg_idx + 1] == "-l" {
		list_elf_symbols(lib_path)
		return
	}

	mut base_addr := u64(0)
	mut local_handle := voidptr(0)

	if target_pid > 0 {
		println("[*] Mode: Remote Attach (PID: ${target_pid})")
		module_short := os.file_name(lib_path)
		base_addr = C.get_remote_module_base(target_pid, &char(module_short.str))
		if base_addr == 0 {
			println("[-] Error: Module ${module_short} not mapped in PID ${target_pid}")
			return
		}
		println("[+] Target Base in PID ${target_pid}: 0x" + base_addr.hex_full())
	} else {
		println("[*] Mode: Local Execution (dlopen)")
		mut loaded_map := map[string]bool{}
		load_dependencies_recursive(lib_path, mut loaded_map)

		local_handle = C.dlopen(&char(lib_path.str), 1)
		if isnil(local_handle) {
			println("[-] Error: Failed to load library " + lib_path)
			return
		}
		base_addr = get_base_address(os.file_name(lib_path))
		if base_addr == 0 {
			println("[-] Error: Base address not found.")
			C.dlclose(local_handle)
			return
		}
	}

	mut steps := [][]string{}
	mut current_step := []string{}
	for i := start_arg_idx + 1; i < os.args.len; i++ {
		if os.args[i] == "::" {
			if current_step.len > 0 {
				steps << current_step
				current_step = []string{}
			}
		} else {
			current_step << os.args[i]
		}
	}
	if current_step.len > 0 {
		steps << current_step
	}

	mut named_buffers := map[string]LocalBuffer{}
	mut step_returns := []voidptr{}

	for step_idx, step in steps {
		if step.len == 0 { continue }
		sym_name := step[0]
		println("\n[!] === Executing Step " + (step_idx + 1).str() + " (" + sym_name + ") ===")

		if sym_name.starts_with("sleep:") {
			parts := sym_name.split(":")
			if parts.len >= 2 {
				ms := parts[1].int()
				time.sleep(ms * time.millisecond)
				println('[+] Slept for ' + ms.str() + ' ms')
			}
			step_returns << voidptr(0)
			continue
		}

		if sym_name.starts_with("alloc:") {
			parts := sym_name.split(":")
			if parts.len >= 3 {
				name := parts[1]
				size := parts[2].int()
				unsafe {
					ptr := malloc(size)
					if !isnil(ptr) {
						C.memset(ptr, 0, usize(size))
						named_buffers[name] = LocalBuffer{ ptr: ptr, size: size }
						println('[+] Pre-allocated `' + name + '` (' + size.str() + ' bytes)')
						step_returns << ptr
					}
				}
			}
			continue
		}

		offset := find_elf_symbol_offset(lib_path, sym_name)
		if offset == 0 {
			println("[-] Error: Symbol not found in ELF: " + sym_name)
			break
		}

		target_addr := base_addr + offset
		println("[+] Target Offset: 0x" + offset.hex_full() + " | Address: 0x" + target_addr.hex_full())

		mut args := []voidptr{}
		mut ret_format := "hex"

		for i := 1; i < step.len; i++ {
			arg_str := step[i]
			if arg_str.starts_with("->") {
				ret_format = arg_str.substr(2, arg_str.len)
			} else if arg_str.starts_with("s:") {
				val_str := arg_str.substr(2, arg_str.len)
				args << voidptr(val_str.str)
			} else if arg_str.starts_with("p:") {
				val_str := arg_str.substr(2, arg_str.len)
				if val_str in named_buffers {
					args << (named_buffers[val_str] or { LocalBuffer{} }).ptr
				} else if val_str.starts_with("$") {
					ref_idx := val_str.substr(1, val_str.len).int() - 1
					if ref_idx >= 0 && ref_idx < step_returns.len {
						args << step_returns[ref_idx]
					} else {
						args << voidptr(0)
					}
				} else {
					hex_val := strconv.parse_uint(val_str.replace("0x", ""), 16, 64) or { 0 }
					args << voidptr(hex_val)
				}
			} else if arg_str.starts_with("$") {
				ref_idx := arg_str.substr(1, arg_str.len).int() - 1
				if ref_idx >= 0 && ref_idx < step_returns.len {
					args << step_returns[ref_idx]
				} else {
					args << voidptr(0)
				}
			} else {
				args << voidptr(arg_str.int())
			}
		}

		mut step_res := voidptr(0)

		if target_pid > 0 {
			mut remote_args := []u64{}
			for a in args {
				remote_args << u64(a)
			}
			res := C.remote_call_arch(target_pid, target_addr, remote_args.len, remote_args.data)
			step_res = voidptr(res)
		} else {
			unsafe {
				C.signal(11, voidptr(C.v_segfault_handler))
				C.signal(7, voidptr(C.v_segfault_handler))
				if C.safe_sigsetjmp() == 0 {
					match args.len {
						0 {
							func := Call0(voidptr(target_addr))
							step_res = func()
						}
						1 {
							func := Call1(voidptr(target_addr))
							step_res = func(args[0])
						}
						2 {
							func := Call2(voidptr(target_addr))
							step_res = func(args[0], args[1])
						}
						3 {
							func := Call3(voidptr(target_addr))
							step_res = func(args[0], args[1], args[2])
						}
						4 {
							func := Call4(voidptr(target_addr))
							step_res = func(args[0], args[1], args[2], args[3])
						}
						5 {
							func := Call5(voidptr(target_addr))
							step_res = func(args[0], args[1], args[2], args[3], args[4])
						}
						6 {
							func := Call6(voidptr(target_addr))
							step_res = func(args[0], args[1], args[2], args[3], args[4], args[5])
						}
						7 {
							func := Call7(voidptr(target_addr))
							step_res = func(args[0], args[1], args[2], args[3], args[4], args[5], args[6])
						}
						8 {
							func := Call8(voidptr(target_addr))
							step_res = func(args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7])
						}
						else {
							println("[-] Error: Max 8 arguments supported.")
						}
					}
				} else {
					println("[-] Segmentation Fault captured safely.")
				}
				C.signal(11, voidptr(0))
				C.signal(7, voidptr(0))
			}
		}

		match ret_format {
			"string", "str" {
				if u64(step_res) != 0 {
					println("[+] Return (String): " + unsafe { (&char(step_res)).vstring() })
				} else {
					println("[+] Return (String): NULL")
				}
			}
			"int" { println("[+] Return (Int): " + i64(step_res).str()) }
			"bool" { println("[+] Return (Bool): " + (u64(step_res) != 0).str()) }
			else { println("[+] Return (Hex): 0x" + u64(step_res).hex_full()) }
		}

		step_returns << step_res
	}

	for _, buf_info in named_buffers {
		unsafe { free(buf_info.ptr) }
	}
	if !isnil(local_handle) {
		C.dlclose(local_handle)
	}
}
