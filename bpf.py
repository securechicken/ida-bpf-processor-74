import ida_idaapi
import ida_idp, ida_ua, ida_xref, ida_name, ida_lines, ida_problems, ida_bytes

def SIGNEXT(x, b):
	m = 1 << (b - 1)
	x = x & ((1 << b) - 1)
	return (x ^ m) - m

BPF_INST_SIZE = 8
BPF_MAX_OPERAND_COUNT = 3

class BPF_CLASS:
	BPF_LD = 0x00
	BPF_LDX = 0x01
	BPF_ST = 0x02
	BPF_STX = 0x03
	BPF_ALU = 0x04
	BPF_JMP = 0x05
	BPF_RET = 0x06
	BPF_MISC = 0x07

class BPF_SIZE:
	BPF_W = 0x00
	BPF_H = 0x08
	BPF_B = 0x10

class BPF_MODE:
	BPF_IMM = 0x00
	BPF_ABS = 0x20
	BPF_IND = 0x40
	BPF_MEM = 0x60
	BPF_LEN = 0x80
	BPF_MSH = 0xa0

class BPF_OP:
	BPF_ADD = 0x00
	BPF_SUB = 0x10
	BPF_MUL = 0x20
	BPF_DIV = 0x30
	BPF_OR = 0x40
	BPF_AND = 0x50
	BPF_LSH = 0x60
	BPF_RSH = 0x70
	BPF_NEG = 0x80
	BPF_MOD = 0x90
	BPF_XOR = 0xa0
	BPF_JA = 0x00
	BPF_JEQ = 0x10
	BPF_JGT = 0x20
	BPF_JGE = 0x30
	BPF_JSET = 0x40

class BPF_SRC:
	BPF_K = 0x00
	BPF_X = 0x08

class BPF_RVAL:
	BPF_K = 0x00
	BPF_X = 0x08
	BPF_A = 0x10

class BPF_MISCOP:
	BPF_TAX = 0x00
	BPF_TXA = 0x80

class BPFi(object):
	class Code(object):
		def __init__(self, code):
			self.kls = (code) & 0x07
			self.size = (code) & 0x18
			self.mode = (code) & 0xe0
			self.op = (code) & 0xf0
			self.src = (code) & 0x08
			self.rval = (code) & 0x18
			self.miscop = (code) & 0xf8
	def __init__(self, c, t, f, k):
		self.c = c
		self.i = BPFi.Code(c)
		self.jt = t
		self.jf = f
		self.k = k


class BpfProc(ida_idp.processor_t):
	NEGATIVE_BRANCH = 0x00
	POSITIVE_BRANCH = 0x01
	M_BASE = 0x04
	FORCE_ENUM = 0x0b

	id = 0x8000 + 8888
	flag = ida_idp.PR_ADJSEGS | ida_idp.PRN_HEX
	cnbits = 8
	dnbits = 8
	psnames = ["bpf"]
	plnames = ["BPF"]
	segreg_size = 0
	instruc_start = 0
	assembler = {
		"header": [".bpf"],
		"flag": ida_idp.AS_NCHRE | ida_idp.ASH_HEXF0 | ida_idp.ASD_DECF0 | ida_idp.ASO_OCTF0 | ida_idp.ASB_BINF0,
		"uflag": 0,
		"name": "b-p-f",
		"origin": ".org",
		"end": ".end",
		"cmnt": ";",
		"ascsep": "\"",
		"accsep": "'",
		"esccodes": "\"'",
		"a_ascii": ".ascii",
		"a_byte": ".byte",
		"a_word": ".word",
		"a_dword": ".dword",
		"a_bss": "dfs %s",
		"a_seg": "seg",
		"a_curip": "PC",
		"a_public": "",
		"a_weak": "",
		"a_extrn": ".extern",
		"a_comdef": "",
		"a_align": ".align",
		"lbrace": "(",
		"rbrace": ")",
		"a_mod": "%",
		"a_band": "&",
		"a_bor": "|",
		"a_xor": "^",
		"a_bnot": "~",
		"a_shl": "<<",
		"a_shr": ">>",
		"a_sizeof_fmt": "size %s",
	}

	def emu_operand(self, op, insn, feature):
		if op.type == ida_ua.o_mem:
			insn.add_dref(op.addr, 0, ida_xref.dr_R)
		elif op.type == ida_ua.o_near:
			# Name label accordincly; can only be labels from branch instructions
			assert op.addr % 8 == 0, f"Unaligned address at offset {op.addr}"
			n = f"@_{op.addr/8}"
			ida_name.set_name(op.addr, n, ida_name.SN_AUTO)
			insn.add_cref(op.addr, insn.ea, ida_xref.fl_JN)

	def notify_emu(self, insn):
		feature = insn.get_canon_feature()
		# Max operand count
		for i in range(BPF_MAX_OPERAND_COUNT):
			oprnd = insn[i]
			if oprnd.type == ida_ua.o_void:
				# No more operands
				break
			self.emu_operand(oprnd, insn, feature)
		if not feature & ida_idp.CF_STOP:
			insn.add_cref(insn.ea + insn.size, insn.ea, ida_xref.fl_F)
		return True

	def notify_out_operand(self, ctx, op):
		out_symbol = ctx.out_symbol
		OutValue = ctx.out_value
		out_name_expr = ctx.out_name_expr
		out_register = ctx.out_register
		outLong = ctx.out_long
		out_tagoff = ctx.out_tagoff
		out_tagon = ctx.out_tagon
		OutLong = ctx.out_long
		if op.type == ida_ua.o_phrase:
			opv = ida_ua.op_t()
			opv.type = ida_ua.o_imm
			opv.value = 4
			# No prefix
			OutValue(opv, ida_ua.OOFW_32)
			out_symbol("*")
			out_symbol("(")
			out_symbol("[")
			# No prefix
			OutValue(op, ida_ua.OOFW_32)
			out_symbol("]")
			out_symbol("&")
			opv.value = 0x0f
			# No prefix
			OutValue(opv, ida_ua.OOFW_32)
			out_symbol(")")
			return True
		elif op.type == ida_ua.o_displ:
			out_symbol("[")
			out_register(self.reg_names[op.reg])
			out_symbol("+")
			# No prefix
			OutValue(op, ida_ua.OOFW_32)
			out_symbol("]")
			return True
		elif op.type == ida_ua.o_reg:
			out_register(self.reg_names[op.reg])
			return True
		elif op.type == ida_ua.o_imm:
			# No prefix
			OutValue(op, ida_ua.OOFW_32)
			return True
		elif op.type == ida_ua.o_mem:
			# Is scratch memory
			if op.specval & BpfProc.M_BASE:
				out_register("M")
			out_symbol("[")
			# No prefix
			OutValue(op, ida_ua.OOF_ADDR)
			out_symbol("]")
			return True
		elif op.type == ida_ua.o_near:
			r = out_name_expr(op, op.addr, ida_idaapi.BADADDR)
			if not r:
				out_tagon(ida_lines.COLOR_ERROR)
				OutLong(op.addr, 16)
				out_tagoff(ida_lines.COLOR_ERROR)
				ida_problems.remember_problem(ida_problems.cvar.PR_NONAME, op.addr)
			return True
		return False

	def notify_out_insn(self, ctx):
		feature = ctx.insn.get_canon_feature()
		ctx.out_mnemonic()
		if feature & ida_idp.CF_USE1:
			ctx.out_one_operand(0)
		if feature & ida_idp.CF_USE2:
			ctx.out_char(",")
			ctx.out_char(" ")
			ctx.out_one_operand(1)
		if feature & ida_idp.CF_USE3:
			ctx.out_char(",")
			ctx.out_char(" ")
			ctx.out_one_operand(2)
		ctx.set_gen_cmt()
		ctx.flush_outbuf()
		return

	def notify_ana(self, insn):
		insn.size = BPF_INST_SIZE
		ea = insn.ea
		c = ida_bytes.get_word(ea)
		jt = ida_bytes.get_wide_byte(ea+2)
		jf = ida_bytes.get_wide_byte(ea+3)
		k = ida_bytes.get_wide_dword(ea+4)
		print("BPF OP:", c, jt, jf, k)
		bi = BPFi(c, jt, jf, k)
		# Initialize operands to voids
		for i in range(BPF_MAX_OPERAND_COUNT+1):
			insn[i].type = ida_ua.o_void
		# Set the instruction index
		insn.itype = 0 # TODO REMOVE
		op_count = 0
		inscls = bi.i.kls
		if inscls == BPF_CLASS.BPF_MISC:
			op_count = self.decode_misc(bi, insn)
		elif inscls == BPF_CLASS.BPF_RET:
			op_count = self.decode_ret(bi, insn)
		elif inscls in [BPF_CLASS.BPF_LD, BPF_CLASS.BPF_LDX]:
			op_count = self.decode_ld(bi, insn)
		elif inscls == BPF_CLASS.BPF_JMP:
			op_count = self.decode_jmp(bi, insn)
		elif inscls in [BPF_CLASS.BPF_ST, BPF_CLASS.BPF_STX]:
			op_count = self.decode_store(bi, insn)
		elif inscls == BPF_CLASS.BPF_ALU:
			op_count = self.decode_alu(bi, insn)
		assert op_count <= BPF_MAX_OPERAND_COUNT, f"Operand count of {op_count} exceeds max of {BPF_MAX_OPERAND_COUNT}"
		return insn.size

	def __init__(self):
		ida_idp.processor_t.__init__(self)
		self.reg_names = [
			"A", "x", "len",
			# virutal
			"CS",
			"M"
		]
		self.reg_first_sreg = self.reg_names.index("CS")
		self.reg_code_sreg = self.reg_names.index("CS")
		self.reg_last_sreg = self.reg_names.index("M")
		self.reg_data_sreg = self.reg_names.index("M")
		self.instruc = [
			# ALU
			{"name": "add", "feature": ida_idp.CF_USE1 | ida_idp.CF_USE2},
			{"name": "sub", "feature": ida_idp.CF_USE1 | ida_idp.CF_USE2},
			{"name": "mul", "feature": ida_idp.CF_USE1 | ida_idp.CF_USE2},
			{"name": "div", "feature": ida_idp.CF_USE1 | ida_idp.CF_USE2},
			{"name": "or", "feature": ida_idp.CF_USE1 | ida_idp.CF_USE2},
			{"name": "and", "feature": ida_idp.CF_USE1 | ida_idp.CF_USE2},
			{"name": "lsh", "feature": ida_idp.CF_USE1 | ida_idp.CF_USE2},
			{"name": "rsh", "feature": ida_idp.CF_USE1 | ida_idp.CF_USE2},
			{"name": "neg", "feature": ida_idp.CF_USE1},
			{"name": "mod", "feature": ida_idp.CF_USE1 | ida_idp.CF_USE2},
			{"name": "xor", "feature": ida_idp.CF_USE1 | ida_idp.CF_USE2},
			# MISC
			{"name": "tax", "feature": 0},
			{"name": "txa", "feature": 0},
			# STORE
			{"name": "stx", "feature": ida_idp.CF_USE1 | ida_idp.CF_CHG1},
			{"name": "st", "feature": ida_idp.CF_USE1 | ida_idp.CF_CHG1},
			# LOAD
			{"name": "ldx", "feature": ida_idp.CF_USE1},
			{"name": "ld", "feature": ida_idp.CF_USE1},
			{"name": "ldh", "feature": ida_idp.CF_USE1},
			{"name": "ldb", "feature": ida_idp.CF_USE1},
			# BRANCH
			{"name": "jne", "feature": ida_idp.CF_STOP | ida_idp.CF_USE1 | ida_idp.CF_USE2 | ida_idp.CF_USE3},
			{"name": "jeq", "feature": ida_idp.CF_STOP | ida_idp.CF_USE1 | ida_idp.CF_USE2 | ida_idp.CF_USE3},
			{"name": "jle", "feature": ida_idp.CF_STOP | ida_idp.CF_USE1 | ida_idp.CF_USE2 | ida_idp.CF_USE3},
			{"name": "jgt", "feature": ida_idp.CF_STOP | ida_idp.CF_USE1 | ida_idp.CF_USE2 | ida_idp.CF_USE3},
			{"name": "jlt", "feature": ida_idp.CF_STOP | ida_idp.CF_USE1 | ida_idp.CF_USE2 | ida_idp.CF_USE3},
			{"name": "jge", "feature": ida_idp.CF_STOP | ida_idp.CF_USE1 | ida_idp.CF_USE2 | ida_idp.CF_USE3},
			{"name": "jnset", "feature": ida_idp.CF_STOP | ida_idp.CF_USE1 | ida_idp.CF_USE2 | ida_idp.CF_USE3},
			{"name": "jset", "feature": ida_idp.CF_STOP | ida_idp.CF_USE1 | ida_idp.CF_USE2 | ida_idp.CF_USE3},
			{"name": "jmp", "feature": ida_idp.CF_STOP | ida_idp.CF_USE1},
			# RETURN
			{"name": "ret", "feature": ida_idp.CF_STOP | ida_idp.CF_USE1},
		]
		self.instruc_end = len(self.instruc)
		self.iname2index = {}
		for idx, ins in enumerate(self.instruc):
			self.iname2index[ins["name"]] = idx

	def decode_ld(self, bi, cmd):
		c = bi.i
		isldx = c.kls == BPF_CLASS.BPF_LDX
		if isldx:
			cmd.itype = self.iname2index["ldx"]
			if c.mode == BPF_MODE.BPF_MSH:
				cmd[0].type = ida_ua.o_phrase
				cmd[0].dtyp = ida_ua.dt_word
				cmd[0].value = SIGNEXT(bi.k,32)
				return 1
		else:
			cmd.itype = self.iname2index["ld"+{
								BPF_SIZE.BPF_W:"",
								BPF_SIZE.BPF_H:"h",
								BPF_SIZE.BPF_B:"b"
							}[c.size]]
			if c.mode == BPF_MODE.BPF_ABS:
				cmd[0].type = ida_ua.o_mem
				cmd[0].dtyp = ida_ua.dt_word
				cmd[0].addr = bi.k
				return 1
			elif c.mode == BPF_MODE.BPF_IND:
				cmd[0].type = ida_ua.o_displ
				cmd[0].dtyp = ida_ua.dt_word
				cmd[0].value = SIGNEXT(bi.k,32)
				cmd[0].reg = self.reg_names.index("x")
				return 1
		if isldx or (c.size == BPF_SIZE.BPF_W):
			if c.mode == BPF_MODE.BPF_IMM:
				cmd[0].type = ida_ua.o_imm
				cmd[0].dtyp = ida_ua.dt_word
				cmd[0].value = bi.k
				return 1
			elif c.mode == BPF_MODE.BPF_LEN:
				cmd[0].type = ida_ua.o_reg
				cmd[0].dtyp = ida_ua.dt_word
				cmd[0].reg = self.reg_names.index("len")
				return 1
			elif c.mode == BPF_MODE.BPF_MEM:
				cmd[0].type = ida_ua.o_mem
				cmd[0].dtyp = ida_ua.dt_word
				cmd[0].addr = bi.k
				# M as base
				cmd[0].specval |= BpfProc.M_BASE
				return 1

	def decode_ret(self, bi, cmd):
		cmd.itype = self.iname2index["ret"]
		if bi.i.rval == BPF_RVAL.BPF_K:
			cmd[0].type = ida_ua.o_imm
			cmd[0].dtyp = ida_ua.dt_word
			cmd[0].value = bi.k
			cmd[0].specval |= BpfProc.FORCE_ENUM
			# TODO: defined values for seccomp?
		elif bi.i.rval == BPF_RVAL.BPF_A:
			cmd[0].type = ida_ua.o_reg
			cmd[0].dtyp = ida_ua.dt_word
			cmd[0].reg = self.reg_names.index("A")
		else:
			# X not supported
			pass 
		return 1

	def decode_jmp(self, bi, cmd):
		c = bi.i
		curr_off = cmd.ea + cmd.size
		cmd.itype = self.iname2index[{
							BPF_OP.BPF_JA:"jmp",
							BPF_OP.BPF_JEQ:"jeq",
							BPF_OP.BPF_JGE:"jge",
							BPF_OP.BPF_JGT:"jgt",
							BPF_OP.BPF_JSET:"jset"
						}[c.op]]
		if c.op == BPF_OP.BPF_JA: 
			cmd[0].type = ida_ua.o_near
			cmd[0].dtyp = ida_ua.dt_word
			cmd[0].addr = curr_off + (bi.k * BPF_INST_SIZE)
			return 1
		immi = 0
		jti = 1
		jfi = 2
		# If the true offset == 0, then use fake negative compares so arrows would be parsed correctly
		if bi.jt == 0: 
			jfi = 1
			jti = 2
			cmd.itype = self.iname2index[{
								BPF_OP.BPF_JEQ:"jne",
								BPF_OP.BPF_JGE:"jlt",
								BPF_OP.BPF_JGT:"jle",
								BPF_OP.BPF_JSET:"jnset"
							}[c.op]]
			# Switch labels
			cmd[jti].specval = BpfProc.NEGATIVE_BRANCH
			cmd[jfi].specval = BpfProc.POSITIVE_BRANCH
		else:
			cmd[jti].specval = BpfProc.POSITIVE_BRANCH
			cmd[jfi].specval = BpfProc.NEGATIVE_BRANCH
		cmd[immi].type = ida_ua.o_imm
		cmd[immi].dtyp = ida_ua.dt_word
		cmd[immi].value = SIGNEXT(bi.k, 32)
		cmd[jti].type = ida_ua.o_near
		cmd[jti].dtyp = ida_ua.dt_byte
		cmd[jti].addr = curr_off + (bi.jt * BPF_INST_SIZE)
		cmd[jfi].type = ida_ua.o_near
		cmd[jfi].dtyp = ida_ua.dt_byte
		cmd[jfi].addr = curr_off + (bi.jf * BPF_INST_SIZE)
		return 3

	def decode_misc(self, bi, cmd):
		c = bi.i
		cmd.itype = self.iname2index[{
							BPF_MISCOP.BPF_TAX: "tax",
							BPF_MISCOP.BPF_TXA: "txa"
						}[c.miscop]]
		return 0

	def decode_store(self, bi, cmd):
		c = bi.i
		cmd.itype = self.iname2index[{
							BPF_CLASS.BPF_ST: "st",
							BPF_CLASS.BPF_STX: "stx"
						}[c.kls]]
		cmd[0].type = ida_ua.o_mem
		cmd[0].dtyp = ida_ua.dt_word
		cmd[0].addr = bi.k
		# M as base
		cmd[0].specval |= BpfProc.M_BASE
		return 1
	
	def decode_alu(self, bi, cmd):
		"""
		BPF_ADD		= 0x00
		BPF_SUB		= 0x10
		BPF_MUL		= 0x20
		BPF_DIV		= 0x30
		BPF_OR		= 0x40
		BPF_AND		= 0x50
		BPF_LSH		= 0x60
		BPF_RSH		= 0x70
		BPF_NEG		= 0x80
		"""
		c = bi.i
		cmd.itype = self.iname2index[{
			BPF_OP.BPF_ADD:"add",
			BPF_OP.BPF_SUB:"sub",
			BPF_OP.BPF_MUL:"mul",
			BPF_OP.BPF_DIV:"div",
			BPF_OP.BPF_OR:"or",
			BPF_OP.BPF_AND:"and",
			BPF_OP.BPF_LSH:"lsh",
			BPF_OP.BPF_RSH:"rsh",
			BPF_OP.BPF_NEG:"neg",
			BPF_OP.BPF_MOD:"mod",
			BPF_OP.BPF_XOR:"xor"
		}[c.op]]
		# assert bi.i.rval == BPF_RVAL.BPF_A
		cmd[0].type = ida_ua.o_reg
		cmd[0].dtyp = ida_ua.dt_word
		cmd[0].reg = self.reg_names.index("A")
		if c.op != BPF_OP.BPF_NEG:
			if bi.i.src == BPF_RVAL.BPF_X:
				cmd[1].type = ida_ua.o_reg
				cmd[1].dtyp = ida_ua.dt_word
				cmd[1].reg = self.reg_names.index("x")
			elif bi.i.src == BPF_RVAL.BPF_K:
				cmd[1].type = ida_ua.o_imm
				cmd[1].dtyp = ida_ua.dt_word
				cmd[1].value = bi.k
			else:
				assert False, bi.i.rval
			return 2
		return 1

def PROCESSOR_ENTRY():
	return BpfProc()
