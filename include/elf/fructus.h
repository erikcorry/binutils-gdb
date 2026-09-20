/* Fructus ELF support for BFD.
   Copyright (C) 2026 Free Software Foundation, Inc.

   This file is part of BFD, the Binary File Descriptor library.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   Inc., 51 Franklin Street - Fifth Floor, Boston, MA 02110-1301, USA.  */

#ifndef _ELF_FRUCTUS_H
#define _ELF_FRUCTUS_H

#include "elf/reloc-macros.h"

/* Relocation types.  Fructus needs no relocation of its own: every address in
   a Fructus program is a plain 8- or 16-bit field, absolute or relative to the
   address of the next instruction, so these four are the generic ones under
   local names.  See isa/fructus.toml's [[reloc]] entries, which the
   assembler's table is generated from.

   The pc-relative pair are biased to the end of the instruction rather than to
   the field's own address; `pcrel_offset' true in the howto, and md_pcrel_from
   returning the address after the instruction, are the two halves of that.  */
START_RELOC_NUMBERS (elf_fructus_reloc_type)
  RELOC_NUMBER (R_FRUCTUS_NONE,      0)
  RELOC_NUMBER (R_FRUCTUS_8,         1)  /* #d8, and any 8-bit datum.  */
  RELOC_NUMBER (R_FRUCTUS_16,        2)  /* jmp/call abs16, mov #imm16, dw.  */
  RELOC_NUMBER (R_FRUCTUS_8_PCREL,   3)  /* br, brclear, brset, jmpr.  */
  RELOC_NUMBER (R_FRUCTUS_16_PCREL,  4)  /* jmpr rel16, callr rel16.  */
END_RELOC_NUMBERS (R_FRUCTUS_max)

#endif /* _ELF_FRUCTUS_H */
