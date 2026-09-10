/* tc-fructus.h -- Header file for tc-fructus.c.
   Copyright (C) 2026 Free Software Foundation, Inc.

   This file is part of GAS, the GNU Assembler.

   GAS is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3, or (at your option)
   any later version.

   GAS is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License along
   with GAS; see the file COPYING.  If not, write to the Free Software
   Foundation, 51 Franklin Street - Fifth Floor, Boston, MA 02110-1301, USA.  */

#define TC_FRUCTUS 1

/* Little endian, and not an option: isa/fructus.toml declares
   `endian = "little"' for data, and 16-bit immediates are stored low byte
   first inside instructions to match.  A -EB switch would be a lie.  */
#define TARGET_BYTES_BIG_ENDIAN 0

#define TARGET_FORMAT	"elf32-fructus"
#define TARGET_ARCH	bfd_arch_fructus

#define WORKING_DOT_WORD

#define md_undefined_symbol(NAME)	0

/* Instructions are byte-granular and unaligned access is free, so gas never
   needs to pad a section.  */
#define md_section_align(SEGMENT, SIZE)	(SIZE)

#define md_number_to_chars		number_to_chars_littleendian

/* `jmpr' is the one instruction with two widths - a 2-byte form reaching
   -128..127 and a 3-byte form reaching the whole address space - so it is the
   one instruction that relaxes.  Everything else has a single encoding once
   its operands are known.  */
#define TC_GENERIC_RELAX_TABLE md_relax_table
extern const relax_typeS md_relax_table[];
