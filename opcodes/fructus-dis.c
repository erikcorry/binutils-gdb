/* Disassemble Fructus instructions.

   This file is part of the GNU Binutils.  It is free software; you can
   redistribute it and/or modify it under the terms of the GNU General Public
   License as published by the Free Software Foundation; either version 3, or
   (at your option) any later version.  */

#include "sysdep.h"
#include <stdio.h>
#define STATIC_TABLE
#define DEFINE_TABLE

#include "opcode/fructus.h"
#include "opcode/fructus-asm.h"
#include "disassemble.h"

/* Fructus is byte-granular and variable length, and an instruction's length is
   a function of its FIRST BYTE alone.  That is a documented commitment of the
   ISA, so this disassembler never looks ahead: read one byte, learn the length,
   read the rest.  Nothing here has to resynchronise.

   PRINTING IS DRIVEN BY THE SPEC'S OWN SYNTAX.  fructus_form_by_opcode takes a
   first byte to a row of the generated form table, and that row carries both
   the syntax to print and the bit positions to read - so this file contains no
   per-instruction format strings at all.

   That is not tidiness, it is the fix for a bug that recurred three times.  An
   itype is a bit LAYOUT and not a syntax, and several layouts serve more than
   one syntax:

     ld rd, [ra, #imm3]   and  add rd, ra, #imm3      one layout, brackets or not
     mov rd, #immbit5     and  add rd, rd, #immbit5   one layout, two operands or three
     add r0, r0, #1                                   pinned - a bare mnemonic is
                                                      not reassemblable

   A printer keyed on the layout gets the punctuation of whichever instruction
   it was written for and is wrong for the rest.  Keyed on the syntax it cannot
   be.  */

/* WHICH FORM.  Length is a function of byte 0 - the ISA commits to that - but
   THE MNEMONIC IS NOT: the unary block packs sxt8, clz and popcount into opcode
   0x32 and separates them with two bits of byte 1.  So byte 0 selects a list
   and byte 1 picks from it, first match winning, in the same order
   tools/decode.js tries them.  A flat 256-entry name table disassembles clz as
   sxt8, which is a plausible-looking listing naming the wrong instruction.  */

static const fructus_form *
fructus_form_for (unsigned char b0, unsigned char b1)
{
  int i;

  for (i = fructus_opcode_first[b0]; i < fructus_opcode_first[b0 + 1]; i++)
    if ((b1 & fructus_opcode_cand[i].mask) == fructus_opcode_cand[i].match)
      return &fructus_forms[fructus_opcode_cand[i].form];

  return NULL;
}

static int
print_operands (struct disassemble_info *info, const fructus_opc_info_t *op,
		unsigned char b0, unsigned char b1, unsigned char b2,
		bfd_vma addr)
{
  fprintf_styled_ftype fpr = info->fprintf_styled_func;
  void *stream = info->stream;
  const fructus_form *f = fructus_form_for (b0, b1);
  unsigned long word;
  long v[8];
  unsigned int i, k;
  const char *p;

  if (f == NULL)
    return fpr (stream, dis_style_text, "; no form for opcode 0x%02x", b0);

  /* The instruction as one word, byte 0 in the most significant position - the
     same orientation the form table's place list is written in.  */
  word = ((unsigned long) b0 << 16) | ((unsigned long) b1 << 8) | b2;
  word >>= 8 * (3 - f->nbytes);

  /* Pull each slot's value out.  A pinned slot carries the value the form fixes
     it at; a tied one repeats another slot, which is why ties are resolved in a
     second pass.  */
  for (i = 0; i < f->nslots; i++)
    v[i] = f->slots[i].fixed ? f->slots[i].value : 0;
  for (k = 0; k < f->nplaces; k++)
    {
      const fructus_place *pl = &f->places[k];
      unsigned long mask = (1UL << pl->width) - 1;

      v[pl->slot] |= (long) (((word >> pl->ilo) & mask) << pl->vlo);
    }
  for (i = 0; i < f->nslots; i++)
    if (f->slots[i].tie >= 0)
      v[i] = v[f->slots[i].tie];

  /* condimm5 is one five-bit index printed in two places, so the constant half
     reads the index its condition half holds.  */
  for (i = 0; i < f->nslots; i++)
    if (f->slots[i].kind == FR_CK && i > 0 && f->slots[i - 1].kind == FR_CC)
      v[i] = fructus_condimm5_imm[v[i - 1] & 31];

  for (p = f->syntax; *p; p++)
    {
      const fructus_opnd *o;
      long x;

      if (*p != '%')
	{
	  fpr (stream, dis_style_text, "%c", *p);
	  continue;
	}
      i = *++p - '0';
      o = &f->slots[i];
      x = v[i];

      switch (o->kind)
	{
	case FR_REG:
	  fpr (stream, dis_style_register, "%s", fructus_reg_names[x & 7]);
	  break;

	case FR_COND:
	  fpr (stream, dis_style_mnemonic, "%s", fructus_cond_names[x & 7]);
	  break;

	case FR_CC:
	  fpr (stream, dis_style_mnemonic, "%s", fructus_condimm5_cond[x & 31]);
	  break;

	case FR_CK:
	  fpr (stream, dis_style_immediate, "%ld", x);
	  break;

	case FR_TABLE:
	  {
	    /* Convert from the index in the instruction to its immediate value.  */
	    const unsigned short *t = NULL;

	    switch (o->table)
	      {
	      case FR_T_IMM3:    t = fructus_imm3;    break;
	      case FR_T_SHIFT3:  t = fructus_shift3;  break;
	      case FR_T_IMMBIT5: t = fructus_immbit5; break;
	      case FR_T_IMMASK5: t = fructus_immask5; break;
	      default: break;
	      }
	    if (t == NULL)
	      fpr (stream, dis_style_text, "?");
	    else if (o->table == FR_T_IMM3 || o->table == FR_T_SHIFT3)
	      fpr (stream, dis_style_immediate, "%d", (short) t[x & 7]);
	    else
	      fpr (stream, dis_style_immediate, "0x%04x", t[x & 31]);
	  }
	  break;

	default:		/* FR_INT */
	  if (o->pcrel)
	    {
	      /* A displacement is measured from the address of the next instruction,
		 not from the field, so the length is part of the sum.  */
	      long d = x;

	      if (o->bits < 32 && (d & (1L << (o->bits - 1))))
		d -= 1L << o->bits;
	      info->print_address_func ((addr + f->nbytes + d) & 0xffff, info);
	    }
	  else if (o->fixed || o->bits == 0)
	    fpr (stream, dis_style_immediate, "%d", (short) x);
	  else if (o->is_signed && (x & (1L << (o->bits - 1))))
	    fpr (stream, dis_style_immediate, "%ld", x - (1L << o->bits));
	  else if (o->bits >= 16)
	    fpr (stream, dis_style_immediate, "0x%04lx", x & 0xffff);
	  else
	    fpr (stream, dis_style_immediate, "%ld", x);
	  break;
	}
    }

  (void) op;
  (void) b2;
  return 0;
}

int
print_insn_fructus (bfd_vma addr, struct disassemble_info *info)
{
  fprintf_styled_ftype fpr = info->fprintf_styled_func;
  void *stream = info->stream;
  bfd_byte buf[3] = { 0, 0, 0 };
  const fructus_opc_info_t *op;
  int status;

  /* One byte is enough to know the length - that is the whole point of
     length_from_first_byte.  */
  if ((status = info->read_memory_func (addr, buf, 1, info)))
    {
      info->memory_error_func (status, addr, info);
      return -1;
    }

  op = &fructus_opc_info[buf[0]];
  if (op->name == NULL)
    {
      fpr (stream, dis_style_assembler_directive, ".byte");
      fpr (stream, dis_style_immediate, "\t0x%02x", buf[0]);
      return 1;
    }

  if (op->length > 1
      && (status = info->read_memory_func (addr + 1, buf + 1, op->length - 1, info)))
    {
      info->memory_error_func (status, addr + 1, info);
      return -1;
    }

  {
    const fructus_form *f = fructus_form_for (buf[0], buf[1]);

    /* The NAME comes from the form, not from the 256-entry table: three unary
       ops share opcode 0x32.  */
    fpr (stream, dis_style_mnemonic, "%s", f != NULL ? f->mnemonic : op->name);

    /* Whether there are operands to print is a property of the SYNTAX, not of
       the length: `add r0, r0, #1' is one byte with all three operands pinned,
       and printing it as a bare `add' gives a listing that will not reassemble.
       Only ret, nop, halt and the like have no syntax at all.  */
    if (f != NULL && f->syntax[0] != '\0')
      {
	fpr (stream, dis_style_text, "\t");
	print_operands (info, op, buf[0], buf[1], buf[2], addr);
      }
  }

  return op->length;
}
