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
#include "disassemble.h"

/* Fructus is byte-granular and variable length, and an instruction's length is
   a function of its FIRST BYTE alone.  That is a documented commitment of the
   ISA, so this disassembler never looks ahead: read one byte, learn the length,
   read the rest.  Nothing here has to resynchronise.

   Byte 1, where there is one, has one of a small number of layouts, and which
   one is the opcode's itype.  The operand fields sit in fixed places within it:

     ddd a aa ss     destination, source, and two bits left over
     aaa i iiii      one register and a five-bit field
     ccc b bb ee     a condition and two registers

   so the extractors below are shared by every itype that uses that shape.  */

#define REG(n)   fructus_reg_names[(n) & 7]
#define D(b1)    REG ((b1) >> 5)          /* byte1[7:5] - dest, or a lone reg */
#define A(b1)    REG (((b1) >> 2) & 7)    /* byte1[4:2] - ALU port A */
#define B(b1,op) REG ((((b1) & 3) << 1) | ((op) & 1))
                                          /* byte1[1:0] + opcode[0] - port B */

/* A five-bit field is read through one of three tables, or as a signed
   integer.  An index is not a value: byte 1 of `add rd, ra, #imm3` holds 6 and
   the programmer wrote #8.  */
#define F5(b1)   ((b1) & 0x1f)
#define SX5(b1)  ((int) ((F5 (b1) ^ 0x10) - 0x10))

static int
print_operands (struct disassemble_info *info, const fructus_opc_info_t *op,
		unsigned char b0, unsigned char b1, unsigned char b2,
		bfd_vma addr)
{
  fprintf_styled_ftype fpr = info->fprintf_styled_func;
  void *stream = info->stream;
  /* A displacement is measured from the address of the NEXT instruction, not
     from the field, so the length is part of the sum.  Getting this wrong
     produces listings that are off by the instruction length and look
     plausible.  */
  bfd_vma next = addr + op->length;
  int imm16 = b1 | (b2 << 8);
  /* A PC-relative displacement ALWAYS ENDS ITS INSTRUCTION - that holds over
     the whole spec and tools/gen-asm.js asserts it - so it is the last byte,
     which is byte 1 of a two-byte jmpr and byte 2 of every three-byte branch.
     Reading b2 unconditionally makes the short jmpr disassemble as a branch to
     itself, which is a plausible-looking listing and not an obvious wrong
     answer.  */
  int off8 = (int) ((signed char) (op->length == 2 ? b1 : b2));

  switch (op->itype)
    {
    case FRUCTUS_1B_NONE:
      return 0;

    case FRUCTUS_2B_REG:
      return fpr (stream, dis_style_register, "%s", D (b1));

    case FRUCTUS_2B_REG_REG:
      return fpr (stream, dis_style_register, "%s, %s", D (b1), A (b1));

    case FRUCTUS_2B_REG_REG_REG:
      return fpr (stream, dis_style_register, "%s, %s, %s",
		  D (b1), A (b1), B (b1, b0));

    case FRUCTUS_2B_IMM5_REG:
      return fpr (stream, dis_style_immediate, "%s, %s, #%d",
		  D (b1), D (b1), SX5 (b1));

    case FRUCTUS_2B_IMMBIT5_REG:
      return fpr (stream, dis_style_immediate, "%s, %s, #0x%04x",
		  D (b1), D (b1), fructus_immbit5[F5 (b1)]);

    case FRUCTUS_2B_IMMASK5_REG:
      return fpr (stream, dis_style_immediate, "%s, %s, #0x%04x",
		  D (b1), D (b1), fructus_immask5[F5 (b1)]);

    case FRUCTUS_2B_IMM3_REG_REG:
      /* The index is {byte1[1:0], opcode[0]} - the same three bits that carry
	 ALU port B, which is why a three-register form and an imm3 form are
	 the same layout with a different reading.  */
      return fpr (stream, dis_style_immediate, "%s, %s, #%d",
		  D (b1), A (b1),
		  (short) fructus_imm3[(((b1) & 3) << 1) | (b0 & 1)]);

    case FRUCTUS_2B_REG_REG_SHIFT3:
      return fpr (stream, dis_style_immediate, "%s, %s, #%d",
		  D (b1), A (b1),
		  (short) fructus_shift3[(((b1) & 3) << 1) | (b0 & 1)]);

    case FRUCTUS_3B_IMM10_REG_REG:
      {
	int v = ((b1 & 3) << 8) | b2;
	v = (v ^ 0x200) - 0x200;                 /* sign extend 10 bits */
	return fpr (stream, dis_style_immediate, "%s, %s, #%d", D (b1), A (b1), v);
      }

    case FRUCTUS_3B_INT16_REG:
      return fpr (stream, dis_style_immediate, "%s, #0x%04x", D (b1), imm16);

    case FRUCTUS_2B_OFF8:
      info->print_address_func (next + off8, info);
      return 0;

    case FRUCTUS_3B_INT16:
      info->print_address_func ((bfd_vma) imm16, info);
      return 0;

    case FRUCTUS_3B_COND3_OFF8_REG_REG:
      /* cccb_bbee: the two registers are the other way round from the syntax,
	 so that the comparison is an rsb with no extra multiplexing.  See the
	 br section of isa/fructus.toml.  */
      fpr (stream, dis_style_mnemonic, "%s, ", fructus_cond_names[(b1 >> 5) & 7]);
      fpr (stream, dis_style_register, "%s, %s, ",
	   B (b1, b0), REG ((b1 >> 2) & 7));
      info->print_address_func (next + off8, info);
      return 0;

    case FRUCTUS_3B_CONDIMM5_OFF8_REG:
      fpr (stream, dis_style_mnemonic, "%s, ", fructus_condimm5_cond[F5 (b1)]);
      fpr (stream, dis_style_register, "%s, ", D (b1));
      fpr (stream, dis_style_immediate, "#%d, ", fructus_condimm5_imm[F5 (b1)]);
      info->print_address_func (next + off8, info);
      return 0;

    case FRUCTUS_3B_IMMBIT5_OFF8_REG:
      fpr (stream, dis_style_register, "%s, ", D (b1));
      fpr (stream, dis_style_immediate, "#0x%04x, ", fructus_immbit5[F5 (b1)]);
      info->print_address_func (next + off8, info);
      return 0;

    case FRUCTUS_3B_IMMASK5_OFF8_REG:
      fpr (stream, dis_style_register, "%s, ", D (b1));
      fpr (stream, dis_style_immediate, "#0x%04x, ", fructus_immask5[F5 (b1)]);
      info->print_address_func (next + off8, info);
      return 0;

    default:
      return fpr (stream, dis_style_text, "; unhandled itype %d", op->itype);
    }
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

  fpr (stream, dis_style_mnemonic, "%s", op->name);
  if (op->itype != FRUCTUS_1B_NONE)
    {
      fpr (stream, dis_style_text, "\t");
      print_operands (info, op, buf[0], buf[1], buf[2], addr);
    }

  return op->length;
}
