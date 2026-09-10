/* tc-fructus.c -- Assemble code for Fructus
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

   You should have received a copy of the GNU General Public License
   along with GAS; see the file COPYING.  If not, write to
   the Free Software Foundation, 51 Franklin Street - Fifth Floor,
   Boston, MA 02110-1301, USA.  */

/* THIS FILE KNOWS NO MNEMONICS.  Every instruction, every operand kind and
   every encoding lives in the generated tables in opcodes/fructus-asm.c, which
   tools/gen-asm.js writes from isa/fructus.toml.  What is here is the engine:
   parse the operands a form asks for, decide whether a form accepts them, and
   place the bits.  Grep this file for "add" or "brclear" and you will find
   nothing, which is the property worth keeping - the spec is the only place
   the instruction set is written down.

   FORM SELECTION IS THE WHOLE JOB.  A mnemonic does not determine an encoding:
   `and rd, rd, #4' fits imm5, immbit5, imm3 and imm10, and `and rd, rd,
   #0xff00' fits only immask5 and imm10.  The generated table is sorted
   shortest first, so taking the FIRST form that accepts what was written is
   the "prefer the smaller encoding" rule, and there is no size search here.

   ONE INSTRUCTION RELAXES.  `jmpr' has a 2-byte form reaching -128..127 and a
   3-byte form reaching the whole address space; everything else has a single
   encoding once its operands are known.  md_begin finds that pair by looking
   at the table rather than by knowing its name, and refuses to start if the
   spec ever grows a second one - see find_relax_pair.  */

#include "as.h"
#include "safe-ctype.h"
#include "subsegs.h"
#include "opcode/fructus.h"
#include "opcode/fructus-asm.h"
#include "elf/fructus.h"

/* `;' comments, matching the customasm syntax the spec's own snippets are
   written in, so one source file can be assembled by both.  `#' introduces a
   comment only at the start of a line, which leaves it free to mean
   "immediate" everywhere an operand can appear - the same arrangement m68k
   uses.  */
const char comment_chars[]        = ";";
const char line_separator_chars[] = "";
const char line_comment_chars[]   = "#";

const char FLT_CHARS[] = "rRsSfFdDxXpP";
const char EXP_CHARS[] = "eE";

const char md_shortopts[] = "";
const struct option md_longopts[] = { { NULL, no_argument, NULL, 0 } };
const size_t md_longopts_size = sizeof (md_longopts);

const pseudo_typeS md_pseudo_table[] = { { 0, 0, 0 } };

/* =========================================================================
   Relaxation
   ========================================================================= */

#define FR_RELAX_SHORT	1
#define FR_RELAX_LONG	2

/* rlx_forward and rlx_backward are measured from the START of the frag, and
   the displacement a short jmpr encodes is measured from the end of the
   2-byte instruction - so the reach is the field's reach shifted by 2.  */
const relax_typeS md_relax_table[] =
{
  { 0,   0,    0, 0 },			/* unused: subtypes start at 1 */
  { 129, -126, 2, FR_RELAX_LONG },	/* FR_RELAX_SHORT */
  { 0,   0,    3, 0 }			/* FR_RELAX_LONG */
};

static const fructus_form *relax_short;
static const fructus_form *relax_long;

/* =========================================================================
   The mnemonic index
   ========================================================================= */

struct fructus_mnem
{
  const fructus_form **forms;
  unsigned int n;
};

struct fructus_alias_list
{
  const fructus_alias **aliases;
  unsigned int n;
};

static htab_t form_hash;
static htab_t alias_hash;

/* =========================================================================
   Small helpers
   ========================================================================= */

static char *
skip_ws (char *s)
{
  while (is_whitespace (*s))
    s++;
  return s;
}

/* Parse an expression without disturbing the caller's input pointer.  */

static char *
parse_exp (char *s, expressionS *op)
{
  char *save = input_line_pointer;

  input_line_pointer = s;
  expression (op);
  s = input_line_pointer;
  input_line_pointer = save;
  return s;
}

/* An identifier, for a register or a condition name.  */

static char *
scan_name (char *s, char **start, int *len)
{
  *start = s;
  while (ISALNUM (*s) || *s == '_')
    s++;
  *len = s - *start;
  return s;
}

static int
lookup_name (const fructus_name *tab, unsigned int n,
	     const char *s, int len, int swapped)
{
  unsigned int i;

  for (i = 0; i < n; i++)
    if (tab[i].swapped == swapped
	&& strncmp (tab[i].name, s, len) == 0
	&& tab[i].name[len] == '\0')
      return tab[i].index;

  return -1;
}

static const unsigned short *
value_table (int id, unsigned int *n)
{
  switch (id)
    {
    case FR_T_IMM3:    *n = 8;  return fructus_imm3;
    case FR_T_SHIFT3:  *n = 8;  return fructus_shift3;
    case FR_T_IMMBIT5: *n = 32; return fructus_immbit5;
    case FR_T_IMMASK5: *n = 32; return fructus_immask5;
    default:           *n = 0;  return NULL;
    }
}

static bfd_reloc_code_real_type
reloc_of (int r)
{
  switch (r)
    {
    case FR_R_8:		return BFD_RELOC_8;
    case FR_R_16:		return BFD_RELOC_16;
    case FR_R_8_PCREL:		return BFD_RELOC_8_PCREL;
    case FR_R_16_PCREL:		return BFD_RELOC_16_PCREL;
    default:			return BFD_RELOC_NONE;
    }
}

/* Does a written constant fit an encoded integer field?  This is the spec's
   own rule and not a convenience approximation.  A 16-bit register makes #-1
   and #0xffff the same thing, so a signed field accepts either spelling and
   takes the value modulo 2^16; a field as wide as the register accepts
   anything a programmer could mean by 16 bits.  */

static bool
int_fits (const fructus_opnd *o, offsetT raw)
{
  valueT masked = (valueT) raw & 0xffff;

  if (o->bits >= 16)
    return raw >= -0x8000 && raw <= 0xffff;

  if (!o->is_signed)
    return raw >= 0 && raw <= (offsetT) ((1u << o->bits) - 1);

  return ((masked + (1u << (o->bits - 1))) & 0xffff) < (1u << o->bits);
}

/* =========================================================================
   Parsing one line against one form
   ========================================================================= */

#define FR_MAX_SLOTS 8

struct slotval
{
  int         reg;		/* FR_REG */
  char *      name;		/* FR_COND, FR_CC: the spelling as written */
  int         namelen;
  expressionS ex;		/* every other kind */
};

static bool
parse_slot (const fructus_opnd *o, char **sp, struct slotval *v)
{
  char *s = *sp;

  switch (o->kind)
    {
    case FR_REG:
      {
	char *nm;
	int len;

	s = scan_name (s, &nm, &len);
	if (len == 0)
	  return false;
	v->reg = lookup_name (fructus_reg_accept, fructus_nreg_accept, nm, len, 0);
	if (v->reg < 0)
	  return false;
      }
      break;

    case FR_COND:
    case FR_CC:
      s = scan_name (s, &v->name, &v->namelen);
      if (v->namelen == 0)
	return false;
      break;

    default:
      s = parse_exp (s, &v->ex);
      if (v->ex.X_op == O_absent || v->ex.X_op == O_illegal)
	return false;
      break;
    }

  *sp = s;
  return true;
}

/* Match LINE against FORM's syntax.  Syntax is literal text with %N standing
   for slot N; whitespace in it means "optional whitespace here", which is why
   `add r0,r1,r2' and `add r0, r1, r2' are the same line.  */

static bool
parse_form (const fructus_form *f, char *line, struct slotval *sv)
{
  const char *p = f->syntax;
  char *s = line;

  while (*p)
    {
      if (*p == '%')
	{
	  int n = p[1] - '0';

	  p += 2;
	  s = skip_ws (s);
	  if (!parse_slot (&f->slots[n], &s, &sv[n]))
	    return false;
	}
      else if (is_whitespace (*p))
	p++;
      else
	{
	  s = skip_ws (s);
	  if (*s != *p)
	    return false;
	  s++;
	  p++;
	}
    }

  s = skip_ws (s);
  return is_end_of_stmt (*s);
}

/* =========================================================================
   Does a form ACCEPT what was parsed, and what does it encode to?
   ========================================================================= */

/* Filled in by match_form.  `written' is the value the programmer wrote, which
   is what ties and pinned operands compare against; `encoded' is what goes in
   the bits, and the two differ for a table operand - #8 is written, index 7 is
   encoded.  */
struct matched
{
  valueT written[FR_MAX_SLOTS];
  valueT encoded[FR_MAX_SLOTS];
  bool   known[FR_MAX_SLOTS];	/* false when only a fixup can supply it */
  bool   fixup[FR_MAX_SLOTS];
};

static bool
match_form (const fructus_form *f, struct slotval *sv, struct matched *m)
{
  unsigned int i;

  for (i = 0; i < f->nslots; i++)
    {
      const fructus_opnd *o = &f->slots[i];

      m->known[i] = true;
      m->fixup[i] = false;
      m->written[i] = 0;
      m->encoded[i] = 0;

      switch (o->kind)
	{
	case FR_REG:
	  m->written[i] = m->encoded[i] = sv[i].reg;
	  break;

	case FR_COND:
	  {
	    int idx = lookup_name (fructus_cond_accept, fructus_ncond_accept,
				   sv[i].name, sv[i].namelen, o->swapped);
	    if (idx < 0)
	      return false;
	    m->written[i] = m->encoded[i] = idx;
	  }
	  break;

	case FR_CC:
	  {
	    /* The constant half is the next slot; the generator guarantees the
	       pair is adjacent and in that order.  Both halves choose ONE
	       five-bit index together, and the accept table already holds
	       every spelling of every predicate - `le #3' and `lt #4' are one
	       entry - so this is a lookup and not a search for equivalences.  */
	    unsigned int j = i + 1, k;
	    valueT imm;
	    int idx = -1;

	    if (j >= f->nslots || f->slots[j].kind != FR_CK)
	      return false;
	    if (sv[j].ex.X_op != O_constant)
	      return false;
	    imm = (valueT) sv[j].ex.X_add_number & 0xffff;

	    for (k = 0; k < fructus_ncondimm_accept; k++)
	      if (fructus_condimm_accept[k].imm == imm
		  && strncmp (fructus_condimm_accept[k].cond, sv[i].name,
			      sv[i].namelen) == 0
		  && fructus_condimm_accept[k].cond[sv[i].namelen] == '\0')
		{
		  idx = fructus_condimm_accept[k].index;
		  break;
		}
	    if (idx < 0)
	      return false;
	    m->written[i] = m->encoded[i] = idx;
	  }
	  break;

	case FR_CK:
	  /* Constrains its anchor and encodes nothing of its own.  */
	  if (sv[i].ex.X_op != O_constant)
	    return false;
	  m->written[i] = (valueT) sv[i].ex.X_add_number & 0xffff;
	  break;

	case FR_TABLE:
	  {
	    unsigned int n, k;
	    const unsigned short *tab = value_table (o->table, &n);
	    valueT v;

	    if (sv[i].ex.X_op != O_constant)
	      return false;		/* no relocation can name a table index */
	    v = (valueT) sv[i].ex.X_add_number & 0xffff;
	    for (k = 0; k < n; k++)
	      if (tab[k] == v)
		break;
	    if (k == n)
	      return false;
	    m->written[i] = v;
	    m->encoded[i] = k;
	  }
	  break;

	default:		/* FR_INT */
	  if (o->pcrel)
	    {
	      /* A branch displacement is never known here: it depends on where
		 this instruction lands.  So the field's WIDTH decides whether
		 the form is usable, and the value arrives as a fixup - or, for
		 jmpr, as a relaxation.  */
	      if (o->reloc == FR_R_NONE)
		return false;
	      m->known[i] = false;
	      m->fixup[i] = true;
	    }
	  else if (sv[i].ex.X_op == O_constant)
	    {
	      /* A pinned or tied operand has no field of its own, so `bits' is
		 zero and there is no range to check - what constrains it is
		 the pin or the tie, tested below.  Range-checking it against a
		 zero-width field rejects every value, which quietly costs the
		 one-byte forms: `add r0, r0, #1' would assemble as two bytes
		 and still be correct, so nothing else would notice.  */
	      if (!o->fixed && o->tie < 0 && !int_fits (o, sv[i].ex.X_add_number))
		return false;
	      m->written[i] = m->encoded[i]
		= (valueT) sv[i].ex.X_add_number & 0xffff;
	    }
	  else
	    {
	      /* A symbol fits only a field wide enough to hold a relocation.
		 That is the same "does it fit" test as the constant case, and
		 it is why `mov rd, #label' picks the three-byte form without
		 anything here naming mov.  */
	      if (o->reloc == FR_R_NONE)
		return false;
	      m->known[i] = false;
	      m->fixup[i] = true;
	    }
	  break;
	}
    }

  /* Pinned and tied operands, in a second pass: a tie may point FORWARDS -
     `ld rd, [ra, #off]' ties d to a, and d is written first.  */
  for (i = 0; i < f->nslots; i++)
    {
      const fructus_opnd *o = &f->slots[i];

      if (o->fixed)
	{
	  if (!m->known[i] || m->written[i] != ((valueT) o->value & 0xffff))
	    return false;
	}
      if (o->tie >= 0)
	{
	  if (!m->known[i] || !m->known[o->tie]
	      || m->written[i] != m->written[o->tie])
	    return false;
	}
    }

  return true;
}

/* =========================================================================
   Emitting
   ========================================================================= */

static unsigned long
build_word (const fructus_form *f, struct matched *m)
{
  unsigned long word = f->base;
  unsigned int k;

  for (k = 0; k < f->nplaces; k++)
    {
      const fructus_place *p = &f->places[k];
      unsigned long mask = (1UL << p->width) - 1;

      word |= ((m->encoded[p->slot] >> p->vlo) & mask) << p->ilo;
    }

  return word;
}

static void
put_word (char *buf, unsigned long word, int nbytes)
{
  int i;

  /* Byte 0 of the instruction is the most significant end of the word.  This
     is the INSTRUCTION stream, which is written in the order the fetch unit
     sees it; 16-bit immediates INSIDE an instruction are little-endian, and
     the generated place list has already put their bytes where they go.  */
  for (i = 0; i < nbytes; i++)
    buf[i] = (word >> (8 * (nbytes - 1 - i))) & 0xff;
}

static void
emit_form (const fructus_form *f, struct slotval *sv, struct matched *m)
{
  char *buf = frag_more (f->nbytes);
  unsigned int i;

  put_word (buf, build_word (f, m), f->nbytes);

  for (i = 0; i < f->nslots; i++)
    {
      const fructus_opnd *o = &f->slots[i];
      int size;

      if (!m->fixup[i])
	continue;

      size = o->bits / 8;
      /* Every relocatable field ends its instruction - asserted over the whole
	 spec by tools/gen-asm.js - so this is where it starts.  */
      fix_new_exp (frag_now,
		   buf - frag_now->fr_literal + f->nbytes - size,
		   size, &sv[i].ex, o->pcrel, reloc_of (o->reloc));
    }
}

/* =========================================================================
   Aliases
   ========================================================================= */

/* An alias captures each operand's TEXT unexamined and pastes it into the line
   the target instruction would have been written as.  No types are involved,
   which is why `sub rd, ra, #imm' can become `add rd, ra, #-(imm)' with the
   negation done by the expression parser on the second pass.  */

static char *
capture (char *s, const char *stop, int *len)
{
  char *start = s;
  int depth = 0;

  /* A captured operand never begins with `#'.  Wherever an immediate is
     allowed the syntax spells the `#' out as a literal, so a capture that
     starts with one means this alias is the wrong shape - which is what tells
     `sub rd, ra, #7' apart from `sub rd, ra, rb' when neither capture is
     typed.  Without this the three-register alias matches first and rewrites
     to `rsb rd, #7, ra'.  */
  if (*s == '#')
    {
      *len = 0;
      return s;
    }

  while (!is_end_of_stmt (*s))
    {
      if (*s == '(' || *s == '[')
	depth++;
      else if (*s == ')' || *s == ']')
	{
	  if (depth == 0 && stop && *s == *stop)
	    break;
	  depth--;
	}
      else if (depth == 0 && stop && *s == *stop)
	break;
      s++;
    }

  *len = s - start;
  while (*len > 0 && is_whitespace (start[*len - 1]))
    (*len)--;
  return s;
}

static bool
match_alias (const fructus_alias *a, char *line, char **cap, int *caplen)
{
  const char *p = a->syntax;
  char *s = line;

  while (*p)
    {
      if (*p == '%')
	{
	  int n = p[1] - '0';
	  const char *stop;

	  p += 2;
	  stop = p;
	  while (is_whitespace (*stop))
	    stop++;
	  s = skip_ws (s);
	  cap[n] = s;
	  s = capture (s, *stop ? stop : NULL, &caplen[n]);
	  if (caplen[n] == 0)
	    return false;
	}
      else if (is_whitespace (*p))
	p++;
      else
	{
	  s = skip_ws (s);
	  if (*s != *p)
	    return false;
	  s++;
	  p++;
	}
    }

  s = skip_ws (s);
  return is_end_of_stmt (*s);
}

/* =========================================================================
   md_begin
   ========================================================================= */

/* Find the one instruction that has two widths of the same PC-relative field.
   Detected from the table rather than by name, and required to be unique: a
   second relaxable pair would need a second pair of states in md_relax_table,
   and silently assembling it at the wrong width is exactly the failure this
   refuses to have.  */

static void
find_relax_pair (void)
{
  unsigned int i, j;

  for (i = 0; i < fructus_nforms; i++)
    {
      const fructus_form *a = &fructus_forms[i];

      if (a->nslots != 1 || a->slots[0].kind != FR_INT || !a->slots[0].pcrel)
	continue;

      for (j = i + 1; j < fructus_nforms; j++)
	{
	  const fructus_form *b = &fructus_forms[j];

	  if (strcmp (a->mnemonic, b->mnemonic) != 0
	      || strcmp (a->syntax, b->syntax) != 0
	      || b->nslots != 1 || !b->slots[0].pcrel
	      || a->nbytes == b->nbytes)
	    continue;

	  if (relax_short != NULL)
	    as_fatal (_("internal error: more than one relaxable instruction "
			"(%s and %s); md_relax_table needs a state pair for "
			"each"), relax_short->mnemonic, a->mnemonic);

	  relax_short = a->nbytes < b->nbytes ? a : b;
	  relax_long  = a->nbytes < b->nbytes ? b : a;
	}
    }

  if (relax_short == NULL)
    return;

  if (relax_short->nbytes != md_relax_table[FR_RELAX_SHORT].rlx_length
      || relax_long->nbytes != md_relax_table[FR_RELAX_LONG].rlx_length)
    as_fatal (_("internal error: md_relax_table does not match the %s forms"),
	      relax_short->mnemonic);
}

void
md_begin (void)
{
  unsigned int i;

  form_hash = str_htab_create ();
  alias_hash = str_htab_create ();

  for (i = 0; i < fructus_nforms; i++)
    {
      const fructus_form *f = &fructus_forms[i];
      struct fructus_mnem *m = str_hash_find (form_hash, f->mnemonic);

      if (f->nslots > FR_MAX_SLOTS)
	as_fatal (_("internal error: %s has %u slots, FR_MAX_SLOTS is %d"),
		  f->mnemonic, f->nslots, FR_MAX_SLOTS);

      if (m == NULL)
	{
	  m = XNEW (struct fructus_mnem);
	  m->forms = NULL;
	  m->n = 0;
	  str_hash_insert (form_hash, f->mnemonic, m, 0);
	}
      m->forms = XRESIZEVEC (const fructus_form *, m->forms, m->n + 1);
      m->forms[m->n++] = f;
    }

  for (i = 0; i < fructus_naliases; i++)
    {
      const fructus_alias *a = &fructus_aliases[i];
      struct fructus_alias_list *l = str_hash_find (alias_hash, a->mnemonic);

      if (l == NULL)
	{
	  l = XNEW (struct fructus_alias_list);
	  l->aliases = NULL;
	  l->n = 0;
	  str_hash_insert (alias_hash, a->mnemonic, l, 0);
	}
      l->aliases = XRESIZEVEC (const fructus_alias *, l->aliases, l->n + 1);
      l->aliases[l->n++] = a;
    }

  find_relax_pair ();

  bfd_set_arch_mach (stdoutput, TARGET_ARCH, bfd_mach_fructus);
}

void
md_operand (expressionS *op ATTRIBUTE_UNUSED)
{
}

/* =========================================================================
   md_assemble
   ========================================================================= */

static void
emit_relaxed (const fructus_form *f, struct slotval *sv)
{
  expressionS *ex = &sv[0].ex;
  symbolS *sym;
  offsetT off;
  char *buf;

  if (ex->X_op == O_symbol)
    {
      sym = ex->X_add_symbol;
      off = ex->X_add_number;
    }
  else if (ex->X_op == O_constant)
    {
      sym = abs_section_sym;
      off = ex->X_add_number;
    }
  else
    {
      /* Anything more involved than a symbol plus a constant cannot be
	 measured before the layout is fixed, so take the long form.  */
      struct matched m;

      if (!match_form (relax_long, sv, &m))
	abort ();
      emit_form (relax_long, sv, &m);
      return;
    }

  buf = frag_var (rs_machine_dependent, relax_long->nbytes, 0,
		  FR_RELAX_SHORT, sym, off, NULL);
  (void) buf;
  (void) f;
}

static void
assemble_line (char *str, int depth);

static void
assemble_alias (struct fructus_alias_list *l, char *args, int depth)
{
  unsigned int i;

  for (i = 0; i < l->n; i++)
    {
      const fructus_alias *a = l->aliases[i];
      char *cap[FR_MAX_SLOTS];
      int caplen[FR_MAX_SLOTS];
      char *out, *w;
      const char *p;
      size_t room;

      if (!match_alias (a, args, cap, caplen))
	continue;

      room = strlen (a->body) + 1;
      for (unsigned int k = 0; k < a->nslots; k++)
	room += caplen[k];
      out = XNEWVEC (char, room);

      w = out;
      for (p = a->body; *p; p++)
	if (*p == '%' && ISDIGIT (p[1]))
	  {
	    int n = p[1] - '0';

	    memcpy (w, cap[n], caplen[n]);
	    w += caplen[n];
	    p++;
	  }
	else
	  *w++ = *p;
      *w = '\0';

      assemble_line (out, depth + 1);
      free (out);
      return;
    }

  as_bad (_("invalid operands"));
}

static void
assemble_line (char *str, int depth)
{
  char *op_start, *op_end, *args;
  char saved;
  struct fructus_mnem *mn;
  struct fructus_alias_list *al;
  unsigned int i;
  const fructus_form *best = NULL;
  struct slotval best_sv[FR_MAX_SLOTS];
  struct matched best_m;
  bool long_matched = false;

  if (depth > 4)
    {
      as_bad (_("alias expansion is too deep"));
      return;
    }

  str = skip_ws (str);
  op_start = str;
  for (op_end = str; !is_end_of_stmt (*op_end) && !is_whitespace (*op_end);
       op_end++)
    ;

  if (op_end == op_start)
    {
      as_bad (_("can't find an opcode"));
      return;
    }

  saved = *op_end;
  *op_end = '\0';
  mn = str_hash_find (form_hash, op_start);
  al = str_hash_find (alias_hash, op_start);
  *op_end = saved;

  if (mn == NULL && al == NULL)
    {
      saved = *op_end;
      *op_end = '\0';
      as_bad (_("unknown opcode `%s'"), op_start);
      *op_end = saved;
      return;
    }

  args = skip_ws (op_end);

  /* SHORTEST FIRST.  The table is sorted, so the first form that accepts these
     operands is the smallest one that can encode them.  */
  if (mn != NULL)
    for (i = 0; i < mn->n; i++)
      {
	const fructus_form *f = mn->forms[i];
	struct slotval sv[FR_MAX_SLOTS];
	struct matched m;

	memset (sv, 0, sizeof (sv));
	if (!parse_form (f, args, sv))
	  continue;
	if (!match_form (f, sv, &m))
	  continue;

	if (best == NULL)
	  {
	    best = f;
	    memcpy (best_sv, sv, sizeof (sv));
	    best_m = m;
	    if (f != relax_short)
	      break;		/* nothing else to learn */
	  }
	else if (f == relax_long)
	  {
	    long_matched = true;
	    break;
	  }
      }

  if (best == NULL)
    {
      /* No encoding took these operands.  An alias might still: `mov rd, rs'
	 has no form of its own and becomes `or rd, rs, #0'.  */
      if (al != NULL)
	assemble_alias (al, args, depth);
      else
	{
	  saved = *op_end;
	  *op_end = '\0';
	  as_bad (_("invalid operands for `%s'"), op_start);
	  *op_end = saved;
	}
      return;
    }

  if (best == relax_short && long_matched)
    emit_relaxed (best, best_sv);
  else
    emit_form (best, best_sv, &best_m);
}

void
md_assemble (char *str)
{
  assemble_line (str, 0);
}

/* =========================================================================
   Relaxation callbacks
   ========================================================================= */

int
md_estimate_size_before_relax (fragS *fragP, segT segment)
{
  /* A target outside this section, or one the linker may replace, cannot be
     measured now.  */
  if (S_GET_SEGMENT (fragP->fr_symbol) != segment
      || S_IS_WEAK (fragP->fr_symbol))
    fragP->fr_subtype = FR_RELAX_LONG;

  return md_relax_table[fragP->fr_subtype].rlx_length;
}

void
md_convert_frag (bfd *abfd ATTRIBUTE_UNUSED, segT sec ATTRIBUTE_UNUSED,
		 fragS *fragP)
{
  const fructus_form *f = (fragP->fr_subtype == FR_RELAX_SHORT
			   ? relax_short : relax_long);
  const fructus_opnd *o = &f->slots[0];
  int size = o->bits / 8;
  char *buf = fragP->fr_literal + fragP->fr_fix;

  /* The only slot is the displacement, and the fixup supplies it, so the word
     is just the form's fixed bits.  */
  put_word (buf, f->base, f->nbytes);

  fix_new (fragP, fragP->fr_fix + f->nbytes - size, size,
	   fragP->fr_symbol, fragP->fr_offset, 1, reloc_of (o->reloc));

  fragP->fr_fix += f->nbytes;
  fragP->fr_var = 0;
}

/* =========================================================================
   Fixups and relocations
   ========================================================================= */

void
md_apply_fix (fixS *fixP, valueT *valP, segT seg ATTRIBUTE_UNUSED)
{
  char *buf = fixP->fx_where + fixP->fx_frag->fr_literal;
  offsetT val = *valP;

  switch (fixP->fx_r_type)
    {
    case BFD_RELOC_8_PCREL:
      if (val < -128 || val > 127)
	as_bad_where (fixP->fx_file, fixP->fx_line,
		      _("branch target is %ld bytes away, out of reach of an "
			"8-bit displacement"), (long) val);
      *buf = val;
      break;

    case BFD_RELOC_8:
      if (val < -128 || val > 255)
	as_bad_where (fixP->fx_file, fixP->fx_line,
		      _("value %ld does not fit in a byte"), (long) val);
      *buf = val;
      break;

    case BFD_RELOC_16:
    case BFD_RELOC_16_PCREL:
      number_to_chars_littleendian (buf, val, 2);
      break;

    case BFD_RELOC_32:
      number_to_chars_littleendian (buf, val, 4);
      break;

    case BFD_RELOC_64:
      number_to_chars_littleendian (buf, val, 8);
      break;

    default:
      as_bad_where (fixP->fx_file, fixP->fx_line,
		    _("cannot apply relocation %s"),
		    bfd_get_reloc_code_name (fixP->fx_r_type));
      break;
    }

  if (fixP->fx_addsy == NULL && fixP->fx_pcrel == 0)
    fixP->fx_done = 1;
}

arelent *
tc_gen_reloc (asection *section ATTRIBUTE_UNUSED, fixS *fixp)
{
  arelent *rel;
  bfd_reloc_code_real_type code = fixp->fx_r_type;

  rel = notes_alloc (sizeof (arelent));
  rel->sym_ptr_ptr = notes_alloc (sizeof (asymbol *));
  *rel->sym_ptr_ptr = symbol_get_bfdsym (fixp->fx_addsy);
  rel->address = fixp->fx_frag->fr_address + fixp->fx_where;
  rel->addend = fixp->fx_offset;

  /* THE PC-RELATIVE BIAS.  The linker computes S + A - P with P the address of
     the FIELD, because pcrel_offset is true in the howto.  A Fructus
     displacement is relative to the address of the NEXT INSTRUCTION, and every
     PC-relative field ends its instruction - tools/gen-asm.js asserts that over
     the whole spec - so the next instruction is at P + fx_size, and the
     difference goes in the addend.

     Get this wrong and branches through a relocation come out off by an
     instruction length: they assemble clean and fail at run time.  */
  if (fixp->fx_pcrel)
    rel->addend -= fixp->fx_size;

  rel->howto = bfd_reloc_type_lookup (stdoutput, code);
  if (rel->howto == NULL)
    {
      as_bad_where (fixp->fx_file, fixp->fx_line,
		    _("cannot represent relocation %s in an object file"),
		    bfd_get_reloc_code_name (code));
      return NULL;
    }

  return rel;
}

long
md_pcrel_from (fixS *fixP)
{
  /* The address of the next instruction.  Uniform because every PC-relative
     field ends the instruction it sits in.  */
  return fixP->fx_where + fixP->fx_frag->fr_address + fixP->fx_size;
}

/* =========================================================================
   Odds and ends
   ========================================================================= */

int
md_parse_option (int c ATTRIBUTE_UNUSED, const char *arg ATTRIBUTE_UNUSED)
{
  return 0;
}

void
md_show_usage (FILE *stream ATTRIBUTE_UNUSED)
{
}

const char *
md_atof (int type, char *lit, int *sizep)
{
  return ieee_md_atof (type, lit, sizep, false);
}
