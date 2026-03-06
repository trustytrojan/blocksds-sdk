// SPDX-License-Identifier: Zlib
//
// Copyright (C) 2025 Antonio Niño Díaz

#ifndef EXTERNAL_ELF_H__
#define EXTERNAL_ELF_H__

#include <stdbool.h>
#include <stdint.h>

/// Load an external ELF file (main binary or dependency) for symbol resolution
/// Returns 0 on success, -1 on failure
int external_elf_load(const char *path);

/// Check if any external ELF files have been loaded
bool external_elf_is_loaded(void);

/// Look up a symbol in all loaded external ELF files
/// Returns the symbol's value if found, UINT32_MAX otherwise
uint32_t external_elf_get_symbol_value(const char *name);

/// Free all loaded external ELF files
void external_elf_free_all(void);

#endif // EXTERNAL_ELF_H__