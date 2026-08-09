module main

import os
import strconv

#flag -ldl
#include <dlfcn.h>
#include "helper.h"

fn C.dlopen(filename &char, flags int) voidptr
fn C.dlsym(handle voidptr, symbol &char) voidptr
fn C.dlclose(handle voidptr) int
fn C.memcpy(dest voidptr, src voidptr, n int) voidptr
fn C.memset(dest voidptr, val int, n int) voidptr
fn C.free(ptr voidptr)
fn C.signal(sig int, handler voidptr) voidptr
fn C.v_segfault_handler(sig int)
fn C.safe_sigsetjmp() int

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
			C.memcpy(&ehdr, ehdr_bytes.data, int(sizeof(Elf64_Ehdr)))
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
			C.memcpy(shdrs.data, shdrs_bytes.data, int(sh_num * sh_entsize))
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
			C.memcpy(dyn_entries.data, dyn_bytes.data, int(dyn_shdr.sh_size))
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
			C.memcpy(&ehdr, ehdr_bytes.data, int(sizeof(Elf32_Ehdr)))
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
			C.memcpy(shdrs.data, shdrs_bytes.data, int(sh_num * sh_entsize))
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
			C.memcpy(dyn_entries.data, dyn_bytes.data, int(dyn_shdr.sh_size))
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
			C.memcpy(&ehdr, ehdr_bytes.data, int(sizeof(Elf64_Ehdr)))
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
			C.memcpy(shdrs.data, shdrs_bytes.data, int(sh_num * sh_entsize))
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
			C.memcpy(dyn_entries.data, dyn_bytes.data, int(dyn_shdr.sh_size))
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
			C.memcpy(&ehdr, ehdr_bytes.data, int(sizeof(Elf32_Ehdr)))
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
			C.memcpy(shdrs.data, shdrs_bytes.data, int(sh_num * sh_entsize))
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
			C.memcpy(dyn_entries.data, dyn_bytes.data, int(dyn_shdr.sh_size))
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
			C.memcpy(&ehdr, ehdr_bytes.data, int(sizeof(Elf64_Ehdr)))
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
			C.memcpy(syms.data, syms_bytes.data, int(sym_shdr.sh_size))
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
			C.memcpy(&ehdr, ehdr_bytes.data, int(sizeof(Elf32_Ehdr)))
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
			C.memcpy(syms.data, syms_bytes.data, int(sym_shdr.sh_size))
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
			C.memcpy(&ehdr, ehdr_bytes.data, int(sizeof(Elf64_Ehdr)))
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
			C.memcpy(syms.data, syms_bytes.data, int(sym_shdr.sh_size))
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
			C.memcpy(&ehdr, ehdr_bytes.data, int(sizeof(Elf32_Ehdr)))
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
			C.memcpy(syms.data, syms_bytes.data, int(sym_shdr.sh_size))
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
type Call9 = fn (voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr) voidptr
type Call10 = fn (voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr) voidptr
type Call11 = fn (voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr) voidptr
type Call12 = fn (voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr) voidptr
type Call13 = fn (voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr) voidptr
type Call14 = fn (voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr) voidptr
type Call15 = fn (voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr) voidptr
type Call16 = fn (voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr) voidptr
type Call17 = fn (voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr) voidptr
type Call18 = fn (voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr) voidptr
type Call19 = fn (voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr) voidptr
type Call20 = fn (voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr, voidptr) voidptr

fn main() {
	if os.args.len < 3 {
		println("Usage:")
		println("  " + os.args[0] + " <lib_name_or_path> <symbol_name_or_substring> [arg1] [arg2] [arg3]...")
		println("  " + os.args[0] + " <lib_name_or_path> <symbol_name> [args] :: <symbol_name_2> [args] :: ...")
		println("  " + os.args[0] + " <lib_name_or_path> --list")
		println("Arg prefixes:")
		println("  123             -> Raw integer")
		println("  s:text          -> Pointer to null-terminated C-string")
		println("  p:0x123         -> Hex pointer address")
		println("  alloc:name:size -> Allocate a local buffer of `size` bytes on heap and register it as `name`")
		println("  p:name          -> Pass pointer of registered buffer `name` as argument")
		println("  $1, $2...       -> Pass raw return value of Step 1, Step 2, etc.")
		println("  p:$1, p:$2...   -> Pass pointer return value of Step 1, Step 2, etc.")
		println("  o:int           -> Allocate local int buffer, print output")
		println("  o:string        -> Allocate local 512-byte string buffer, print output")
		println("Pseudo-steps (used as commands, e.g. cmd :: cmd):")
		println("  alloc:name:size                 -> Pre-allocate a zero-initialized buffer on heap")
		println("  set:name:offset:type:value      -> Write data into allocated buffer")
		println("    Supported types: i8, i16, i32, i64, ptr, str, str_ptr")
		println("  dump:name:size                  -> Print buffer hex/ASCII content safely with bounds check")
		println("Return type format (append to arguments):")
		println("  ->string        -> Print return value as C-string")
		println("  ->int           -> Print return value as 64-bit integer")
		println("  ->bool          -> Print return value as boolean")
		println("  ->hex           -> Print return value as hex (default)")
		return
	}

	mut lib_arg := os.args[1]
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

	if os.args[2] == "--list" || os.args[2] == "-l" {
		list_elf_symbols(lib_path)
		return
	}

	mut loaded_map := map[string]bool{}
	println("[*] Detecting dependencies from ELF headers...")
	load_dependencies_recursive(lib_path, mut loaded_map)

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

	mut steps := [][]string{}
	mut current_step := []string{}
	for i := 2; i < os.args.len; i++ {
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

		if sym_name.starts_with("alloc:") {
			parts := sym_name.split(":")
			if parts.len >= 3 {
				name := parts[1]
				size := parts[2].int()
				unsafe {
					ptr := malloc(size)
					if isnil(ptr) {
						println("[-] Error: Allocation failed for `$name` ($size bytes)")
						step_returns << voidptr(0)
					} else {
						C.memset(ptr, 0, size)
						named_buffers[name] = LocalBuffer{ ptr: ptr, size: size }
						println('[+] Pseudo-step: Pre-allocated buffer `' + name + '` (' + size.str() + ' bytes) at ' + ptr.str())
						step_returns << ptr
					}
				}
			} else {
				println("[-] Error: Invalid alloc syntax. Use: alloc:name:size")
				step_returns << voidptr(0)
			}
			continue
		}

		if sym_name.starts_with("set:") {
			parts := sym_name.split(":")
			if parts.len >= 5 {
				buf_name := parts[1]
				offset := parts[2].int()
				val_type := parts[3]
				val_str := parts[4..].join(":")

				if buf_name in named_buffers {
					buf_info := named_buffers[buf_name] or { LocalBuffer{} }
					buf_ptr := buf_info.ptr
					buf_size := buf_info.size
					unsafe {
						target_ptr := voidptr(u64(buf_ptr) + u64(offset))
						mut valid_write := false
						match val_type {
							"i8", "char", "u8" {
								if offset + 1 <= buf_size {
									val := val_str.int()
									*&u8(target_ptr) = u8(val)
									valid_write = true
									println('[+] Pseudo-step: Written ' + val_type + ' (' + val_str + ') into `' + buf_name + '` at offset ' + offset.str())
								}
							}
							"i16", "short", "u16" {
								if offset + 2 <= buf_size {
									val := val_str.int()
									*&u16(target_ptr) = u16(val)
									valid_write = true
									println('[+] Pseudo-step: Written ' + val_type + ' (' + val_str + ') into `' + buf_name + '` at offset ' + offset.str())
								}
							}
							"i32", "int", "u32" {
								if offset + 4 <= buf_size {
									val := val_str.int()
									*&u32(target_ptr) = u32(val)
									valid_write = true
									println('[+] Pseudo-step: Written ' + val_type + ' (' + val_str + ') into `' + buf_name + '` at offset ' + offset.str())
								}
							}
							"i64", "long", "u64" {
								if offset + 8 <= buf_size {
									mut val := u64(0)
									if val_str.starts_with("0x") {
										val = strconv.parse_uint(val_str.replace("0x", ""), 16, 64) or { 0 }
									} else {
										val = strconv.parse_uint(val_str, 10, 64) or { 0 }
									}
									*&u64(target_ptr) = val
									valid_write = true
									println('[+] Pseudo-step: Written ' + val_type + ' (' + val_str + ') into `' + buf_name + '` at offset ' + offset.str())
								}
							}
							"ptr" {
								if offset + int(sizeof(voidptr)) <= buf_size {
									mut ptr_val := voidptr(0)
									if val_str in named_buffers {
										ptr_val = (named_buffers[val_str] or { LocalBuffer{} }).ptr
									} else if val_str.starts_with("0x") {
										hex_val := strconv.parse_uint(val_str.replace("0x", ""), 16, 64) or { 0 }
										ptr_val = voidptr(hex_val)
									} else if val_str.starts_with("$") {
										ref_idx := val_str.substr(1, val_str.len).int() - 1
										if ref_idx >= 0 && ref_idx < step_returns.len {
											ptr_val = step_returns[ref_idx]
										}
									}
									*&voidptr(target_ptr) = ptr_val
									valid_write = true
									println('[+] Pseudo-step: Written pointer (' + ptr_val.str() + ') into `' + buf_name + '` at offset ' + offset.str())
								}
							}
							"str" {
								str_len := val_str.len
								if offset + str_len + 1 <= buf_size {
									C.memcpy(target_ptr, val_str.str, str_len)
									*&u8(voidptr(u64(target_ptr) + u64(str_len))) = 0
									valid_write = true
									println('[+] Pseudo-step: Copied raw string "' + val_str + '" into `' + buf_name + '` at offset ' + offset.str())
								}
							}
							"str_ptr" {
								if offset + int(sizeof(voidptr)) <= buf_size {
									str_ptr := val_str.str
									*&voidptr(target_ptr) = voidptr(str_ptr)
									valid_write = true
									println('[+] Pseudo-step: Written string pointer (' + voidptr(str_ptr).str() + ') to "' + val_str + '" into `' + buf_name + '` at offset ' + offset.str())
								}
							}
							else {}
						}

						if !valid_write {
							println("[-] Error: Out of bounds write blocked on `$buf_name` at offset $offset for type $val_type. Buffer size is $buf_size.")
						}
					}
				} else {
					println("[-] Error: Target buffer `$buf_name` has not been allocated.")
				}
			} else {
				println("[-] Error: Invalid set syntax. Use: set:buf_name:offset:type:value")
			}
			step_returns << voidptr(0)
			continue
		}

		if sym_name.starts_with("dump:") {
			parts := sym_name.split(":")
			if parts.len >= 3 {
				buf_name := parts[1]
				mut size := parts[2].int()
				if buf_name in named_buffers {
					buf_info := named_buffers[buf_name] or { LocalBuffer{} }
					buf_ptr := buf_info.ptr
					buf_size := buf_info.size
					if size > buf_size {
						size = buf_size
					}
					unsafe {
						println('[+] Pseudo-step: Hex/ASCII dump of `' + buf_name + '` (' + size.str() + ' bytes):')
						for offset := 0; offset < size; offset += 16 {
							mut hex_part := ""
							mut ascii_part := ""
							limit := if offset + 16 < size { offset + 16 } else { size }
							for idx := offset; idx < limit; idx++ {
								b := *&u8(voidptr(u64(buf_ptr) + u64(idx)))
								hex_part += '${b:02x} '
								if b >= 32 && b <= 126 {
									ascii_part += b.ascii_str()
								} else {
									ascii_part += "."
								}
							}
							if limit - offset < 16 {
								padding_len := (16 - (limit - offset)) * 3
								hex_part += " ".repeat(padding_len)
							}
							println("    0x${offset:02x}: " + hex_part + " | " + ascii_part)
						}
					}
				} else {
					println("[-] Error: Target buffer `$buf_name` has not been allocated.")
				}
			} else {
				println("[-] Error: Invalid dump syntax. Use: dump:name:size")
			}
			step_returns << voidptr(0)
			continue
		}

		if sym_name.starts_with("dump_sym:") {
			parts := sym_name.split(":")
			if parts.len >= 3 {
				target_sym := parts[1]
				mut size := parts[2].int()
				sym_offset := find_elf_symbol_offset(lib_path, target_sym)
				if sym_offset == 0 {
					println("[-] Error: Symbol not found for dumping: " + target_sym)
				} else {
					sym_ptr := voidptr(base_addr + sym_offset)
					unsafe {
						println('[+] Pseudo-step: Hex/ASCII dump of symbol `' + target_sym + '` at ' + sym_ptr.str() + ' (' + size.str() + ' bytes):')
						for offset := 0; offset < size; offset += 16 {
							mut hex_part := ""
							mut ascii_part := ""
							limit := if offset + 16 < size { offset + 16 } else { size }
							for idx := offset; idx < limit; idx++ {
								b := *&u8(voidptr(u64(sym_ptr) + u64(idx)))
								hex_part += '${b:02x} '
								if b >= 32 && b <= 126 {
									ascii_part += b.ascii_str()
								} else {
									ascii_part += "."
								}
							}
							if limit - offset < 16 {
								padding_len := (16 - (limit - offset)) * 3
								hex_part += " ".repeat(padding_len)
							}
							println("    0x${offset:02x}: " + hex_part + " | " + ascii_part)
						}
					}
				}
			} else {
				println("[-] Error: Invalid dump_sym syntax. Use: dump_sym:symbol_name:size")
			}
			step_returns << voidptr(0)
			continue
		}

		if sym_name.starts_with("set_sym:") {
			parts := sym_name.split(":")
			if parts.len >= 5 {
				target_sym := parts[1]
				offset := parts[2].int()
				val_type := parts[3]
				val_str := parts[4..].join(":")

				sym_offset := find_elf_symbol_offset(lib_path, target_sym)
				if sym_offset == 0 {
					println("[-] Error: Symbol not found for writing: " + target_sym)
				} else {
					sym_ptr := voidptr(base_addr + sym_offset)
					unsafe {
						target_ptr := voidptr(u64(sym_ptr) + u64(offset))
						mut valid_write := false
						match val_type {
							"i8", "char", "u8" {
								val := val_str.int()
								*&u8(target_ptr) = u8(val)
								valid_write = true
							}
							"i16", "short", "u16" {
								val := val_str.int()
								*&u16(target_ptr) = u16(val)
								valid_write = true
							}
							"i32", "int", "u32" {
								val := val_str.int()
								*&u32(target_ptr) = u32(val)
								valid_write = true
							}
							"i64", "long", "u64" {
								mut val := u64(0)
								if val_str.starts_with("0x") {
									val = strconv.parse_uint(val_str.replace("0x", ""), 16, 64) or { 0 }
								} else {
									val = strconv.parse_uint(val_str, 10, 64) or { 0 }
								}
								*&u64(target_ptr) = val
								valid_write = true
							}
							"float", "f32" {
								val := val_str.f32()
								*&f32(target_ptr) = val
								valid_write = true
							}
							else {}
						}
						if valid_write {
							println('[+] Pseudo-step: Written ' + val_type + ' (' + val_str + ') into symbol `' + target_sym + '` at offset ' + offset.str())
						} else {
							println("[-] Error: Unsupported or invalid write type: " + val_type)
						}
					}
				}
			} else {
				println("[-] Error: Invalid set_sym syntax. Use: set_sym:symbol_name:offset:type:value")
			}
			step_returns << voidptr(0)
			continue
		}

		offset := find_elf_symbol_offset(lib_path, sym_name)
		if offset == 0 {
			println("[-] Error: Symbol not found in ELF headers: " + sym_name)
			break
		}

		println("[+] Symbol Offset: 0x" + offset.hex_full())
		target_addr := voidptr(base_addr + offset)
		println("[+] Target Memory Address: " + target_addr.str())

		mut args := []voidptr{}
		mut out_buffers := []voidptr{}
		mut out_types := []string{}
		mut out_indices := []int{}
		mut ret_format := "hex"
		mut step_args := []string{}

		for i := 1; i < step.len; i++ {
			arg_str := step[i]
			if arg_str.starts_with("->") {
				ret_format = arg_str.substr(2, arg_str.len)
			} else {
				step_args << arg_str
			}
		}

		for i := 0; i < step_args.len; i++ {
			arg_str := step_args[i]
			if arg_str.starts_with("alloc:") {
				parts := arg_str.split(":")
				if parts.len >= 3 {
					name := parts[1]
					size := parts[2].int()
					if name in named_buffers {
						args << (named_buffers[name] or { LocalBuffer{} }).ptr
					} else {
						unsafe {
							ptr := malloc(size)
							C.memset(ptr, 0, size)
							named_buffers[name] = LocalBuffer{ ptr: ptr, size: size }
							args << ptr
						}
					}
				} else {
					args << voidptr(0)
				}
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
			} else if arg_str == "o:int" {
				unsafe {
					mut local_buf := &int(malloc(int(sizeof(int))))
					if !isnil(local_buf) {
						*local_buf = 0
						args << voidptr(local_buf)
						out_buffers << voidptr(local_buf)
						out_types << "int"
						out_indices << i
					}
				}
			} else if arg_str == "o:string" {
				unsafe {
					mut local_buf := malloc(512)
					if !isnil(local_buf) {
						*&u8(local_buf) = 0
						args << voidptr(local_buf)
						out_buffers << voidptr(local_buf)
						out_types << "string"
						out_indices << i
					}
				}
			} else if arg_str.starts_with("s:") {
				val_str := arg_str.substr(2, arg_str.len)
				args << voidptr(val_str.str)
			} else {
				args << voidptr(arg_str.int())
			}
		}

		println("[!] Calling function with " + args.len.str() + " args...")
		mut success := false
		mut step_res := voidptr(0)

		unsafe {
			C.signal(11, voidptr(C.v_segfault_handler))
			C.signal(7, voidptr(C.v_segfault_handler))
			if C.safe_sigsetjmp() == 0 {
				match args.len {
					0 {
						func := Call0(target_addr)
						step_res = func()
					}
					1 {
						func := Call1(target_addr)
						step_res = func(args[0])
					}
					2 {
						func := Call2(target_addr)
						step_res = func(args[0], args[1])
					}
					3 {
						func := Call3(target_addr)
						step_res = func(args[0], args[1], args[2])
					}
					4 {
						func := Call4(target_addr)
						step_res = func(args[0], args[1], args[2], args[3])
					}
					5 {
						func := Call5(target_addr)
						step_res = func(args[0], args[1], args[2], args[3], args[4])
					}
					6 {
						func := Call6(target_addr)
						step_res = func(args[0], args[1], args[2], args[3], args[4], args[5])
					}
					7 {
						func := Call7(target_addr)
						step_res = func(args[0], args[1], args[2], args[3], args[4], args[5], args[6])
					}
					8 {
						func := Call8(target_addr)
						step_res = func(args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7])
					}
					9 {
						func := Call9(target_addr)
						step_res = func(args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8])
					}
					10 {
						func := Call10(target_addr)
						step_res = func(args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8], args[9])
					}
					11 {
						func := Call11(target_addr)
						step_res = func(args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8], args[9], args[10])
					}
					12 {
						func := Call12(target_addr)
						step_res = func(args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8], args[9], args[10], args[11])
					}
					13 {
						func := Call13(target_addr)
						step_res = func(args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8], args[9], args[10], args[11], args[12])
					}
					14 {
						func := Call14(target_addr)
						step_res = func(args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8], args[9], args[10], args[11], args[12], args[13])
					}
					15 {
						func := Call15(target_addr)
						step_res = func(args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8], args[9], args[10], args[11], args[12], args[13], args[14])
					}
					16 {
						func := Call16(target_addr)
						step_res = func(args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8], args[9], args[10], args[11], args[12], args[13], args[14], args[15])
					}
					17 {
						func := Call17(target_addr)
						step_res = func(args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8], args[9], args[10], args[11], args[12], args[13], args[14], args[15], args[16])
					}
					18 {
						func := Call18(target_addr)
						step_res = func(args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8], args[9], args[10], args[11], args[12], args[13], args[14], args[15], args[16], args[17])
					}
					19 {
						func := Call19(target_addr)
						step_res = func(args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8], args[9], args[10], args[11], args[12], args[13], args[14], args[15], args[16], args[17], args[18])
					}
					20 {
						func := Call20(target_addr)
						step_res = func(args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8], args[9], args[10], args[11], args[12], args[13], args[14], args[15], args[16], args[17], args[18], args[19])
					}
					else {
						println("[-] Error: Unsupported number of arguments.")
					}
				}
				success = true
				match ret_format {
					"string", "str" {
						if u64(step_res) != 0 {
							println("[+] Return (String): " + (&char(step_res)).vstring())
						} else {
							println("[+] Return (String): NULL")
						}
					}
					"int" {
						println("[+] Return (Int): " + i64(step_res).str())
					}
					"bool" {
						println("[+] Return (Bool): " + (u64(step_res) != 0).str())
					}
					else {
						println("[+] Return (Hex): 0x" + u64(step_res).hex_full())
					}
				}
			} else {
				println("[-] Error: Execution was aborted due to a Segmentation Fault (SIGSEGV/SIGBUS).")
			}
			C.signal(11, voidptr(0))
			C.signal(7, voidptr(0))
		}

		if u64(step_res) == 0xffffffff || u64(step_res) == 0xffffffffffffffff {
			println("[-] Error: Step " + (step_idx + 1).str() + " failed (returned -1). Aborting chain to prevent crash.")
			break
		}
		step_returns << step_res
		if success {
			for idx, buf in out_buffers {
				unsafe {
					if out_types[idx] == "int" {
						println("[+] Output buffer at Argument #" + out_indices[idx].str() + " updated to: " + (*&int(buf)).str())
					} else if out_types[idx] == "string" {
						println("[+] Output buffer at Argument #" + out_indices[idx].str() + " updated to: " + (&char(buf)).vstring())
					}
				}
			}
		} else {
			break
		}
	}

	for _, buf_info in named_buffers {
		unsafe { free(buf_info.ptr) }
	}
	C.dlclose(handle)
}
