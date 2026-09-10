/* BFD support for the Fructus processor.
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

#include "sysdep.h"
#include "bfd.h"
#include "libbfd.h"

/* Sixteen bits in a word AND sixteen in an address, inside an elf32
   container.  elf32 is the file format, unrelated to the target register width.

   Section alignment power is 1.  Instructions are byte-granular and the
   hardware permits unaligned loads with no penalty - see the memory notes in
   isa/fructus.toml - so nothing REQUIRES two, but 16-bit data is the common
   case and a default of one costs at most a byte per section.  */

const bfd_arch_info_type bfd_fructus_arch =
{
  16,			/* Bits in a word.  */
  16,			/* Bits in an address.  */
  8,			/* Bits in a byte.  */
  bfd_arch_fructus,	/* Architecture number.  */
  bfd_mach_fructus,	/* Machine number.  */
  "fructus",		/* Architecture name.  */
  "fructus",		/* Printable name.  */
  1,			/* Section alignment power.  */
  true,			/* The one and only.  */
  bfd_default_compatible,
  bfd_default_scan,
  bfd_arch_default_fill,
  NULL,
  0			/* Maximum offset of a reloc from the start of an insn.  */
};
