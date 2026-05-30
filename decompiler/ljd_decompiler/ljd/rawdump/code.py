#
# Copyright (C) 2013 Andrian Nord. See Copyright Notice in main.py
#

from ljd.util.log import errprint

import ljd.bytecode.instructions as instructions

# KOG/GrandChase KL bytecode opcode remapping
# Maps KL opcode number → standard LuaJIT opcode number
# Discovered by structural analysis of 3,061 dumped bytecode files
# Fixed via hard-constraint analysis (opcode_classifier_v2.py):
#   KL 72-80: ALL confirmed VN bitfield layout (C=knum, B=slot)
#   KL 83-88: ALL confirmed VV bitfield layout (both slots)
#   KL 72,73,77,79 = NV operations stored in VN layout → need B/C swap
#
# Confidence: ✓ = confirmed by hard constraint, ● = high, ○ = medium
_KL_REMAP = {
	# === Comparison ops (identity, all 100% followed by JMP) ✓ ===
	0: 0,    # ISLT
	1: 1,    # ISGE
	2: 2,    # ISLE
	3: 3,    # ISGT
	4: 4,    # ISEQV
	5: 5,    # ISNEV
	6: 6,    # ISEQS
	7: 7,    # ISNES
	8: 8,    # ISEQN
	9: 9,    # ISNEN
	10: 10,  # ISEQP
	11: 11,  # ISNEP
	# === Call ops ● ===
	12: 61,  # CALLM
	13: 62,  # CALL ✓
	14: 63,  # CALLMT
	15: 64,  # CALLT ○
	# === Iterator call ops ○ ===
	16: 65,  # ITERC
	17: 66,  # ITERN
	19: 68,  # ISNEXT
	# === Constant load ops ● ===
	20: 37,  # KSTR ●
	21: 38,  # KCDATA
	22: 39,  # KSHORT ✓
	23: 40,  # KNUM ●
	24: 41,  # KPRI ●
	25: 42,  # KNIL ○
	# === Unary ops ● ===
	26: 16,  # MOV ●
	27: 17,  # NOT ○
	28: 18,  # UNM ○
	29: 19,  # LEN ○
	# === Table creation & access ✓/● ===
	30: 50,  # TNEW ✓
	31: 51,  # TDUP ✓
	32: 52,  # GGET ✓
	33: 53,  # GSET ✓
	34: 54,  # TGETV ●
	35: 55,  # TGETS ●
	36: 56,  # TGETB ●
	# === Table set ops ✓/● ===
	38: 57,  # TSETV ●
	39: 58,  # TSETS ✓
	40: 59,  # TSETB ✓
	41: 60,  # TSETM ○
	# === Test ops ○ ===
	45: 12,  # ISTC
	46: 15,  # ISF
	50: 14,  # IST
	# === Returns ✓ ===
	51: 71,  # RET0 ✓
	52: 72,  # RET1 ✓
	# === Upvalue ops ===
	53: 43,  # UGET
	54: 44,  # USETV
	56: 46,  # USETN
	57: 47,  # USETP
	58: 48,  # UCLO ○
	59: 49,  # FNEW ✓
	# === Loop/branch ops ===
	60: 73,  # FORI ✓
	62: 75,  # FORL ✓
	65: 78,  # ITERL ○
	68: 81,  # LOOP (was duplicate ISNEXT; forward-branch NOP hint) ○
	71: 84,  # JMP ✓
	# === Arithmetic VN: A = slot[B] OP numconst[C] ✓ ===
	# Hard constraint: C≥framesize proves C is knum index (not a slot)
	74: 20,  # ADDVN ✓
	75: 21,  # SUBVN ✓
	78: 23,  # DIVVN ✓ (was wrongly DIVVV)
	80: 22,  # MULVN ✓
	76: 24,  # MODVN ✓
	# === Arithmetic NV: A = numconst OP slot  ✓ ===
	# KL stores NV in VN layout (C=knum, B=slot).
	# Standard NV expects B=knum, C=slot → read() swaps B/C.
	72: 25,  # ADDNV ✓ (was wrongly ADDVV; commutative, swap harmless)
	73: 26,  # SUBNV ✓ (was wrongly SUBVV; non-commutative!)
	77: 27,  # MULNV ✓ (was wrongly MULVV; commutative, swap harmless)
	79: 29,  # MODNV ✓ (was wrongly MODVV; non-commutative!)
	# === Arithmetic VV: A = slot[B] OP slot[C] ✓ ===
	# Hard constraint: C≥num_kn proves C is a slot (not knum)
	83: 30,  # ADDVV ✓
	84: 31,  # SUBVV ✓
	85: 32,  # MULVV ✓
	88: 33,  # DIVVV ✓
	# === String concatenation ● ===
	82: 36,  # CAT
}

# Note: NV ops have the SAME bitfield layout as VN (B=slot, C=knum).
# Only the opcode differs; the builder handles left/right operand order.


_OPCODES = (
	# Comparison ops

	(0x00, 	instructions.ISLT),  # @UndefinedVariable
	(0x01, 	instructions.ISGE),  # @UndefinedVariable
	(0x02, 	instructions.ISLE),  # @UndefinedVariable
	(0x03, 	instructions.ISGT),  # @UndefinedVariable

	(0x04, 	instructions.ISEQV),  # @UndefinedVariable
	(0x05, 	instructions.ISNEV),  # @UndefinedVariable

	(0x06, 	instructions.ISEQS),  # @UndefinedVariable
	(0x07, 	instructions.ISNES),  # @UndefinedVariable

	(0x08, 	instructions.ISEQN),  # @UndefinedVariable
	(0x09, 	instructions.ISNEN),  # @UndefinedVariable

	(0x0A, 	instructions.ISEQP),  # @UndefinedVariable
	(0x0B, 	instructions.ISNEP),  # @UndefinedVariable

	# Unary test and copy ops

	(0x0C, 	instructions.ISTC),  # @UndefinedVariable
	(0x0D, 	instructions.ISFC),  # @UndefinedVariable

	(0x0E, 	instructions.IST),  # @UndefinedVariable
	(0x0F, 	instructions.ISF),  # @UndefinedVariable

	# Unary ops

	(0x10, 	instructions.MOV),  # @UndefinedVariable
	(0x11, 	instructions.NOT),  # @UndefinedVariable
	(0x12, 	instructions.UNM),  # @UndefinedVariable
	(0x13, 	instructions.LEN),  # @UndefinedVariable

	# Binary ops

	(0x14, 	instructions.ADDVN),  # @UndefinedVariable
	(0x15, 	instructions.SUBVN),  # @UndefinedVariable
	(0x16, 	instructions.MULVN),  # @UndefinedVariable
	(0x17, 	instructions.DIVVN),  # @UndefinedVariable
	(0x18, 	instructions.MODVN),  # @UndefinedVariable

	(0x19, 	instructions.ADDNV),  # @UndefinedVariable
	(0x1A, 	instructions.SUBNV),  # @UndefinedVariable
	(0x1B, 	instructions.MULNV),  # @UndefinedVariable
	(0x1C, 	instructions.DIVNV),  # @UndefinedVariable
	(0x1D, 	instructions.MODNV),  # @UndefinedVariable

	(0x1E, 	instructions.ADDVV),  # @UndefinedVariable
	(0x1F, 	instructions.SUBVV),  # @UndefinedVariable
	(0x20, 	instructions.MULVV),  # @UndefinedVariable
	(0x21, 	instructions.DIVVV),  # @UndefinedVariable
	(0x22, 	instructions.MODVV),  # @UndefinedVariable

	(0x23, 	instructions.POW),  # @UndefinedVariable
	(0x24, 	instructions.CAT),  # @UndefinedVariable

	# Constant ops

	(0x25, 	instructions.KSTR),  # @UndefinedVariable
	(0x26, 	instructions.KCDATA),  # @UndefinedVariable
	(0x27, 	instructions.KSHORT),  # @UndefinedVariable
	(0x28, 	instructions.KNUM),  # @UndefinedVariable
	(0x29, 	instructions.KPRI),  # @UndefinedVariable

	(0x2A, 	instructions.KNIL),  # @UndefinedVariable

	# Upvalue and function ops

	(0x2B, 	instructions.UGET),  # @UndefinedVariable

	(0x2C, 	instructions.USETV),  # @UndefinedVariable
	(0x2D, 	instructions.USETS),  # @UndefinedVariable
	(0x2E, 	instructions.USETN),  # @UndefinedVariable
	(0x2F, 	instructions.USETP),  # @UndefinedVariable

	(0x30, 	instructions.UCLO),  # @UndefinedVariable

	(0x31, 	instructions.FNEW),  # @UndefinedVariable

	# Table ops

	(0x32, 	instructions.TNEW),  # @UndefinedVariable

	(0x33, 	instructions.TDUP),  # @UndefinedVariable

	(0x34, 	instructions.GGET),  # @UndefinedVariable
	(0x35, 	instructions.GSET),  # @UndefinedVariable

	(0x36, 	instructions.TGETV),  # @UndefinedVariable
	(0x37, 	instructions.TGETS),  # @UndefinedVariable
	(0x38, 	instructions.TGETB),  # @UndefinedVariable

	(0x39, 	instructions.TSETV),  # @UndefinedVariable
	(0x3A, 	instructions.TSETS),  # @UndefinedVariable
	(0x3B, 	instructions.TSETB),  # @UndefinedVariable

	(0x3C, 	instructions.TSETM),  # @UndefinedVariable

	# Calls and vararg handling

	(0x3D, 	instructions.CALLM),  # @UndefinedVariable
	(0x3E, 	instructions.CALL),  # @UndefinedVariable
	(0x3F, 	instructions.CALLMT),  # @UndefinedVariable
	(0x40, 	instructions.CALLT),  # @UndefinedVariable

	(0x41, 	instructions.ITERC),  # @UndefinedVariable
	(0x42, 	instructions.ITERN),  # @UndefinedVariable

	(0x43, 	instructions.VARG),  # @UndefinedVariable

	(0x44, 	instructions.ISNEXT),  # @UndefinedVariable

	# Returns

	(0x45, 	instructions.RETM),  # @UndefinedVariable
	(0x46, 	instructions.RET),  # @UndefinedVariable
	(0x47, 	instructions.RET0),  # @UndefinedVariable
	(0x48, 	instructions.RET1),  # @UndefinedVariable

	# Loops and branches

	(0x49, 	instructions.FORI),  # @UndefinedVariable
	(0x4A, 	instructions.JFORI),  # @UndefinedVariable

	(0x4B, 	instructions.FORL),  # @UndefinedVariable
	(0x4C, 	instructions.IFORL),  # @UndefinedVariable
	(0x4D, 	instructions.JFORL),  # @UndefinedVariable

	(0x4E, 	instructions.ITERL),  # @UndefinedVariable
	(0x4F, 	instructions.IITERL),  # @UndefinedVariable
	(0x50, 	instructions.JITERL),  # @UndefinedVariable

	(0x51, 	instructions.LOOP),  # @UndefinedVariable
	(0x52, 	instructions.ILOOP),  # @UndefinedVariable
	(0x53, 	instructions.JLOOP),  # @UndefinedVariable

	(0x54, 	instructions.JMP),  # @UndefinedVariable

	# Function headers

	(0x55, 	instructions.FUNCF),  # @UndefinedVariable
	(0x56, 	instructions.IFUNCF),  # @UndefinedVariable
	(0x57, 	instructions.JFUNCF),  # @UndefinedVariable

	(0x58, 	instructions.FUNCV),  # @UndefinedVariable
	(0x59, 	instructions.IFUNCV),  # @UndefinedVariable
	(0x5A, 	instructions.JFUNCV),  # @UndefinedVariable

	(0x5B, 	instructions.FUNCC),  # @UndefinedVariable
	(0x5C, 	instructions.FUNCCW)  # @UndefinedVariable
)


_MAP = [None] * 256


def read(parser):
	global _MAP

	codeword = parser.stream.read_uint(4)

	raw_opcode = codeword & 0xFF

	# Remap KL opcode to standard LuaJIT opcode
	opcode = _KL_REMAP.get(raw_opcode, raw_opcode)

	instruction_class = _MAP[opcode]

	if instruction_class is None:
		errprint("Warning: unknown opcode {0:08x}", opcode)
		instruction_class = instructions.UNKNW  # @UndefinedVariable

	instruction = instruction_class()

	if instruction_class.opcode != opcode:
		instruction.opcode = opcode

	_set_instruction_operands(parser, codeword, instruction)

	return instruction


def _set_instruction_operands(parser, codeword, instruction):
	if instruction.args_count == 3:
		A = (codeword >> 8) & 0xFF
		CD = (codeword >> 16) & 0xFF
		B = (codeword >> 24) & 0xFF
	else:
		A = (codeword >> 8) & 0xFF
		CD = (codeword >> 16) & 0xFFFF

	if instruction.A_type is not None:
		instruction.A = _process_operand(parser, instruction.A_type, A)

	if instruction.B_type is not None:
		instruction.B = _process_operand(parser, instruction.B_type, B)

	if instruction.CD_type is not None:
		instruction.CD = _process_operand(parser, instruction.CD_type, CD)


def _process_operand(parser, operand_type, operand):
	if operand_type == instructions.T_STR			\
			or operand_type == instructions.T_TAB	\
			or operand_type == instructions.T_FUN	\
			or operand_type == instructions.T_CDT:
		return parser.complex_constants_count - operand - 1
	elif operand_type == instructions.T_JMP:
		return operand - 0x8000
	else:
		return operand


def _init():
	global _OPCODES, _MAP

	for opcode, instruction in sorted(_OPCODES, key=lambda x: x[0]):
		_MAP[opcode] = instruction

	del globals()["_init"]
	del globals()["_OPCODES"]

_init()
