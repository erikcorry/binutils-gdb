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

/* Relocation types.  Four are the generic ones under local names: a plain
   8- or 16-bit field, absolute or relative to the address of the next
   instruction.  The fifth and sixth, R_FRUCTUS_ZP10 and R_FRUCTUS_16_TAG1,
   are Fructus's own - see below.
   See isa/fructus.toml's [[reloc]] entries, which the assembler's table is
   generated from.

   The pc-relative pair are biased to the end of the instruction rather than to
   the field's own address; `pcrel_offset' true in the howto, and md_pcrel_from
   returning the address after the instruction, are the two halves of that.  */
START_RELOC_NUMBERS (elf_fructus_reloc_type)
  RELOC_NUMBER (R_FRUCTUS_NONE,      0)
  RELOC_NUMBER (R_FRUCTUS_8,         1)  /* #d8, and any 8-bit datum.  */
  RELOC_NUMBER (R_FRUCTUS_16,        2)  /* jmp/call abs16, mov #imm16, dw.  */
  RELOC_NUMBER (R_FRUCTUS_8_PCREL,   3)  /* br, brclr, brset, jmpr.  */
  RELOC_NUMBER (R_FRUCTUS_16_PCREL,  4)  /* jmpr rel16, callr rel16.  */
  RELOC_NUMBER (R_FRUCTUS_ZP10,      5)  /* #zp(sym) in an imm10 field.  */
  RELOC_NUMBER (R_FRUCTUS_16_TAG1,   6)  /* .short tag1(sym): S + A + 1.  */
END_RELOC_NUMBERS (R_FRUCTUS_max)

/* THE ZERO PAGE is 0x0000..0x03ff, reached as [rb, #imm10] with rb holding
   FRUCTUS_ZP_BASE: imm10 is signed, so -512..511 from 0x200 is the whole
   kilobyte.  R_FRUCTUS_ZP10 places S + A - FRUCTUS_ZP_BASE in the field and
   refuses anything outside it.

   The field is split - offset bits 1:0 at the top of byte 1, bits 9:2 in
   byte 2 - but read as the little-endian halfword at byte 1 it is one run,
   bits 15:6, so the howto is an ordinary 16-bit one with bitpos 6.  Byte 1's
   low six bits are registers and are left alone.  tools/gen-asm.js asserts
   that shape over every imm10 form in the spec, and tools/check.js that this
   constant is the spec's.  */
#define FRUCTUS_ZP_BASE 0x200

/* A TAGGED POINTER is the address of a heap object plus FRUCTUS_TAG1: the
   object is 2-aligned, so bit 0 is free to say "this is a pointer".
   R_FRUCTUS_16_TAG1 places S + A + FRUCTUS_TAG1 in a 16-bit datum, written
   `.short tag1(sym)', and refuses an S + A that is odd - a tag on an address
   that was not aligned would be indistinguishable from a different object.
   The datum itself may be at any address, odd or even: a bytecode stream
   is not aligned.  */
#define FRUCTUS_TAG1 1

#endif /* _ELF_FRUCTUS_H */
