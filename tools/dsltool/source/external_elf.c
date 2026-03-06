// SPDX-License-Identifier: Zlib
//
// Copyright (C) 2025 Antonio Niño Díaz

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "elf.h"
#include "log.h"

typedef struct {
    Elf32_Ehdr *hdr;
    int symtab_index;
    size_t symtab_size;
    int strtab_index;
} elf_info;

static elf_info *external_elfs = NULL;
static size_t num_elfs = 0;

int external_elf_load(const char *path)
{
    Elf32_Ehdr *hdr = elf_load(path);
    if (hdr == NULL)
    {
        ERROR("Failed to open external ELF: %s\n", path);
        return -1;
    }

    int symtab_index = -1;
    size_t symtab_size = 0;
    int strtab_index = -1;

    for (unsigned int i = 0; i < hdr->e_shnum; i++)
    {
        const Elf32_Shdr *shdr = elf_section(hdr, i);

        const char *name = elf_get_string_shstrtab(hdr, shdr->sh_name);
        if (name == NULL)
            continue;

        if (shdr->sh_size == 0)
            continue;

        if (strcmp(name, ".strtab") == 0)
        {
            strtab_index = i;
        }
        else if (strcmp(name, ".symtab") == 0)
        {
            symtab_index = i;
            symtab_size = shdr->sh_size;
        }
    }

    if ((symtab_index == -1) || (strtab_index == -1))
    {
        ERROR("External ELF %s missing symtab or strtab\n", path);
        free(hdr);
        return -1;
    }

    elf_info *new_external_elfs = realloc(external_elfs,
                                          sizeof(elf_info) * (num_elfs + 1));
    if (new_external_elfs == NULL)
    {
        ERROR("Memory allocation failed\n");
        free(hdr);
        return -1;
    }

    external_elfs = new_external_elfs;
    external_elfs[num_elfs].hdr = hdr;
    external_elfs[num_elfs].symtab_index = symtab_index;
    external_elfs[num_elfs].symtab_size = symtab_size;
    external_elfs[num_elfs].strtab_index = strtab_index;
    num_elfs++;

    VERBOSE("Loaded external ELF: %s (%zu symbols)\n",
            path, symtab_size / sizeof(Elf32_Sym));

    return 0;
}

bool external_elf_is_loaded(void)
{
    return num_elfs > 0;
}

uint32_t external_elf_get_symbol_value(const char *name)
{
    if ((name == NULL) || (num_elfs == 0))
        return UINT32_MAX;

    for (size_t i = 0; i < num_elfs; i++)
    {
        elf_info *info = &external_elfs[i];
        const Elf32_Sym *sym = elf_section_data(info->hdr, info->symtab_index);
        size_t sym_num = info->symtab_size / sizeof(Elf32_Sym);

        for (size_t s = 0; s < sym_num; s++)
        {
            uint8_t type = ELF_ST_TYPE(sym[s].st_info);

            if ((type != STT_FUNC) && (type != STT_OBJECT) && (type != STT_TLS))
                continue;

            const char *sym_name = elf_get_string_strtab(info->hdr,
                                                          info->strtab_index,
                                                          sym[s].st_name);

            if ((sym_name != NULL) && (strcmp(name, sym_name) == 0))
                return sym[s].st_value;
        }
    }

    return UINT32_MAX;
}

void external_elf_free_all(void)
{
    for (size_t i = 0; i < num_elfs; i++)
        free(external_elfs[i].hdr);

    free(external_elfs);
    external_elfs = NULL;
    num_elfs = 0;
}