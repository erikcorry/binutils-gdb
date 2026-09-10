/* Fructus-specific support for 32-bit ELF.
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

/* Fructus is a 16-bit machine in an elf32 container.  There is no GOT, no PLT,
   no dynamic linking and no MMU, so this file is nearly the minimum an ELF
   backend can be: five relocations, the two lookups, and a relocate_section
   that hands everything to _bfd_final_link_relocate.

   All four real relocations are generic - see include/elf/fructus.h.  */

#include "sysdep.h"
#include "bfd.h"
#include "libbfd.h"
#include "elf-bfd.h"
#include "elf/fructus.h"

/* `pcrel_offset' is true, so the linker computes S + A - P with P the address
   of the field.  A Fructus displacement is relative to the address of the next
   instruction, and the difference is carried in the addend: gas subtracts
   fx_size in tc_gen_reloc, which works uniformly because every pc-relative
   field ends the instruction it sits in.  tools/gen-asm.js asserts that over
   the whole spec.  */

static reloc_howto_type fructus_elf_howto_table [] =
{
  HOWTO (R_FRUCTUS_NONE,	/* type */
	 0,			/* rightshift */
	 0,			/* size */
	 0,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_dont, /* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 "R_FRUCTUS_NONE",	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0,			/* dst_mask */
	 false),		/* pcrel_offset */

  /* An 8-bit absolute datum: the #d8 directive.  */
  HOWTO (R_FRUCTUS_8,
	 0, 1, 8, false, 0,
	 complain_overflow_bitfield,
	 bfd_elf_generic_reloc,
	 "R_FRUCTUS_8",
	 false, 0, 0x00ff, false),

  /* A 16-bit absolute address: jmp, call, mov rd/#imm16, and dw.  Stored low
     byte first, which is what the generic reloc does on a little-endian
     target.  The address space is 16 bits, so every value is in range and
     there is nothing to complain about.  */
  HOWTO (R_FRUCTUS_16,
	 0, 2, 16, false, 0,
	 complain_overflow_dont,
	 bfd_elf_generic_reloc,
	 "R_FRUCTUS_16",
	 false, 0, 0xffff, false),

  /* An 8-bit signed displacement from the next instruction, -128..+127: every
     conditional branch, and the short jmpr.  Out of range is a link error
     rather than a silent wrap.  */
  HOWTO (R_FRUCTUS_8_PCREL,
	 0, 1, 8, true, 0,
	 complain_overflow_signed,
	 bfd_elf_generic_reloc,
	 "R_FRUCTUS_8_PCREL",
	 false, 0, 0x00ff, true),

  /* A 16-bit signed displacement from the next instruction: the long jmpr,
     and callr.  In a 16-bit address space this always fits; the signed
     complaint is kept to catch a relocation applied to the wrong field.  */
  HOWTO (R_FRUCTUS_16_PCREL,
	 0, 2, 16, true, 0,
	 complain_overflow_signed,
	 bfd_elf_generic_reloc,
	 "R_FRUCTUS_16_PCREL",
	 false, 0, 0xffff, true),
};

/* Map BFD reloc types to Fructus ELF reloc types.  */

struct fructus_reloc_map
{
  bfd_reloc_code_real_type bfd_reloc_val;
  unsigned int fructus_reloc_val;
};

static const struct fructus_reloc_map fructus_reloc_map [] =
{
  { BFD_RELOC_NONE,	 R_FRUCTUS_NONE },
  { BFD_RELOC_8,	 R_FRUCTUS_8 },
  { BFD_RELOC_16,	 R_FRUCTUS_16 },
  { BFD_RELOC_8_PCREL,	 R_FRUCTUS_8_PCREL },
  { BFD_RELOC_16_PCREL,	 R_FRUCTUS_16_PCREL },
};

static reloc_howto_type *
fructus_reloc_type_lookup (bfd *abfd ATTRIBUTE_UNUSED,
			   bfd_reloc_code_real_type code)
{
  unsigned int i;

  for (i = 0; i < sizeof (fructus_reloc_map) / sizeof (fructus_reloc_map[0]); i++)
    if (fructus_reloc_map[i].bfd_reloc_val == code)
      return &fructus_elf_howto_table[fructus_reloc_map[i].fructus_reloc_val];

  return NULL;
}

static reloc_howto_type *
fructus_reloc_name_lookup (bfd *abfd ATTRIBUTE_UNUSED, const char *r_name)
{
  unsigned int i;

  for (i = 0;
       i < sizeof (fructus_elf_howto_table) / sizeof (fructus_elf_howto_table[0]);
       i++)
    if (fructus_elf_howto_table[i].name != NULL
	&& strcasecmp (fructus_elf_howto_table[i].name, r_name) == 0)
      return &fructus_elf_howto_table[i];

  return NULL;
}

/* Set the howto pointer for a Fructus ELF reloc.  */

static bool
fructus_info_to_howto_rela (bfd *abfd,
			    arelent *cache_ptr,
			    Elf_Internal_Rela *dst)
{
  unsigned int r_type = ELF32_R_TYPE (dst->r_info);

  if (r_type >= (unsigned int) R_FRUCTUS_max)
    {
      /* xgettext:c-format */
      _bfd_error_handler (_("%pB: unsupported relocation type %#x"),
			  abfd, r_type);
      bfd_set_error (bfd_error_bad_value);
      return false;
    }
  cache_ptr->howto = &fructus_elf_howto_table[r_type];
  return true;
}

/* Relocate a Fructus ELF section.  Every relocation here is generic, so this
   is the standard walk with _bfd_final_link_relocate doing the arithmetic.  */

static int
fructus_elf_relocate_section (struct bfd_link_info *info,
			      bfd *input_bfd,
			      asection *input_section,
			      bfd_byte *contents,
			      Elf_Internal_Rela *relocs,
			      Elf_Internal_Sym *local_syms,
			      asection **local_sections)
{
  Elf_Internal_Shdr *symtab_hdr = &elf_symtab_hdr (input_bfd);
  struct elf_link_hash_entry **sym_hashes = elf_sym_hashes (input_bfd);
  Elf_Internal_Rela *rel;
  Elf_Internal_Rela *relend = relocs + input_section->reloc_count;

  for (rel = relocs; rel < relend; rel++)
    {
      reloc_howto_type *howto;
      unsigned long r_symndx;
      Elf_Internal_Sym *sym = NULL;
      asection *sec = NULL;
      struct elf_link_hash_entry *h = NULL;
      bfd_vma relocation;
      bfd_reloc_status_type r;
      const char *name;
      int r_type;

      r_type = ELF32_R_TYPE (rel->r_info);
      r_symndx = ELF32_R_SYM (rel->r_info);

      if (r_type >= (int) R_FRUCTUS_max)
	{
	  /* xgettext:c-format */
	  _bfd_error_handler (_("%pB: unsupported relocation type %#x"),
			      input_bfd, r_type);
	  bfd_set_error (bfd_error_bad_value);
	  return false;
	}
      howto = fructus_elf_howto_table + r_type;

      if (r_symndx < symtab_hdr->sh_info)
	{
	  sym = local_syms + r_symndx;
	  sec = local_sections[r_symndx];
	  relocation = _bfd_elf_rela_local_sym (info->output_bfd, sym, &sec, rel);

	  name = bfd_elf_string_from_elf_section
	    (input_bfd, symtab_hdr->sh_link, sym->st_name);
	  name = (name == NULL || *name == '\0') ? bfd_section_name (sec) : name;
	}
      else
	{
	  bool unresolved_reloc, warned, ignored;

	  RELOC_FOR_GLOBAL_SYMBOL (info, input_bfd, input_section, rel,
				   r_symndx, symtab_hdr, sym_hashes,
				   h, sec, relocation,
				   unresolved_reloc, warned, ignored);

	  name = h->root.root.string;
	}

      if (sec != NULL && discarded_section (sec))
	RELOC_AGAINST_DISCARDED_SECTION (info, input_bfd, input_section,
					 rel, 1, relend, R_FRUCTUS_NONE,
					 howto, 0, contents);

      if (bfd_link_relocatable (info))
	continue;

      r = _bfd_final_link_relocate (howto, input_bfd, input_section, contents,
				    rel->r_offset, relocation, rel->r_addend);

      if (r != bfd_reloc_ok)
	{
	  const char *msg = NULL;

	  switch (r)
	    {
	    case bfd_reloc_overflow:
	      (*info->callbacks->reloc_overflow)
		(info, (h ? &h->root : NULL), name, howto->name,
		 (bfd_vma) 0, input_bfd, input_section, rel->r_offset);
	      break;

	    case bfd_reloc_undefined:
	      (*info->callbacks->undefined_symbol)
		(info, name, input_bfd, input_section, rel->r_offset, true);
	      break;

	    case bfd_reloc_outofrange:
	      msg = _("internal error: out of range error");
	      break;

	    case bfd_reloc_notsupported:
	      msg = _("internal error: unsupported relocation error");
	      break;

	    case bfd_reloc_dangerous:
	      msg = _("internal error: dangerous relocation");
	      break;

	    default:
	      msg = _("internal error: unknown error");
	      break;
	    }

	  if (msg)
	    (*info->callbacks->warning) (info, msg, name, input_bfd,
					 input_section, rel->r_offset);
	}
    }

  return true;
}

#define ELF_ARCH		bfd_arch_fructus
#define ELF_MACHINE_CODE	EM_FRUCTUS

/* No MMU, and 64 KiB of address space in total.  A 4 KiB page size would let
   the linker spend most of the machine on alignment padding, so this is 4,
   matching the section alignment the arch declares.  msp430 does the same.  */
#define ELF_MAXPAGESIZE		4

#define TARGET_LITTLE_SYM	fructus_elf32_vec
#define TARGET_LITTLE_NAME	"elf32-fructus"

#define elf_info_to_howto_rel			NULL
#define elf_info_to_howto			fructus_info_to_howto_rela
#define elf_backend_relocate_section		fructus_elf_relocate_section

#define elf_backend_can_gc_sections		1
#define elf_backend_rela_normal			1

#define bfd_elf32_bfd_reloc_type_lookup		fructus_reloc_type_lookup
#define bfd_elf32_bfd_reloc_name_lookup		fructus_reloc_name_lookup

#include "elf32-target.h"
