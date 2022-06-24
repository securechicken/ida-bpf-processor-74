import ida_pro, ida_idaapi
import ida_enum, ida_idp, ida_segment, ida_loader, ida_entry, ida_lines, ida_auto

DEFAULT_BPF_FILE_MAGIC = b"bpf\x00"
DEFAULT_BPF_FILE_MAGIC_LEN = len(DEFAULT_BPF_FILE_MAGIC)
DEFAULT_BPF_FILE_RESERVED = b"\x00" * 4
DEFAULT_BPF_FILE_RESERVED_LEN = len(DEFAULT_BPF_FILE_RESERVED)
DEFAULT_BPF_FILE_HEADER_LEN = DEFAULT_BPF_FILE_MAGIC_LEN + DEFAULT_BPF_FILE_RESERVED_LEN

def read_whole_file(li, s=DEFAULT_BPF_FILE_HEADER_LEN):
	li.seek(s)
	return li.read(li.size())

def accept_file(li, n):
	# We support only one format per file
	if ida_pro.IDA_SDK_VERSION < 700 and n > 0:
		return 0
	li.seek(0)
	if li.read(DEFAULT_BPF_FILE_MAGIC_LEN) != DEFAULT_BPF_FILE_MAGIC:
		return 0
	return {"format": "BPF file", "options": 1|0x8000} # accept the file

def setup_enums():
	enums = {"SECCOMP": [
		# http://lxr.free-electrons.com/source/include/uapi/linux/seccomp.h#L28
		("SECCOMP_RET_KILL", 0, "kill the task immediately"),
		("SECCOMP_RET_TRAP",  0x00030000, "disallow and force a SIGSYS"),
		("SECCOMP_RET_ERRNO", 0x00050000, "returns an errno"),
		("SECCOMP_RET_TRACE", 0x7ff00000, "pass to a tracer or disallow"),
		("SECCOMP_RET_ALLOW", 0x7fff0000, "allow")
	],
	"AUDIT_ARCH":[
		("AUDIT_ARCH_I386", 0x40000003, ""),
		("AUDIT_ARCH_X86_64", 0xC000003E, "")
	]}
	for enum_name in enums:
		enum_vals = enums[enum_name]
		repeat_cmnt = 0
		# Index ida_idaapi.BADADDR to append to list; bitmask 0
		enum_id = ida_enum.add_enum(ida_idaapi.BADADDR, enum_name, 0)
		if enum_id == ida_idaapi.BADADDR:
			print("Unable to create enum SECCOMP")
			return -1
		for n,v,c in enum_vals:
			if ida_enum.add_enum_member(enum_id, n, v, -1):
				print(f"Unable to create {n}")
				return -1
			if c:
				const_id = ida_enum.get_enum_member_by_name(n)
				if const_id == -1:
					print(f"Unable to get id for {n}")
					return -1
				if not ida_enum.set_enum_member_cmt(const_id, c, repeat_cmnt):
					print(f"Failed setting comment for {n}")
					return -1
	print("Finished creating enum")

def load_file(li, neflags, format):
	# Select the PC processor module
	ida_idp.set_processor_type("BPF", ida_idp.SETPROC_LOADER_NON_FATAL|ida_idp.SETPROC_LOADER)
	buf = read_whole_file(li)
	if not buf:
		return 0
	start = 0x0
	seg = ida_segment.segment_t()
	size = len(buf)
	end = start + size
	# Create the segment
	seg.start_ea = start
	seg.end_ea = end
	seg.bitness = 1 # 32-bit
	ida_segment.add_segm_ex(seg, "bpf_c", "CODE", 0)
	# Copy the bytes
	ida_loader.mem2base(buf, start, end)
	# Add entry point
	ida_entry.add_entry(start, start, "start", 1) 
	# Add comment to beginning of disassembly
	ida_lines.add_extra_line(start, True, "BPF bytecode disassembly")
	# Mark for analysis
	ida_auto.auto_mark(start, ida_auto.AU_CODE)
	setup_enums()
	return 1
