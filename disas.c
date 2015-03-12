#include "binflow.h"

#define MAX_ARGS 6
#define EDI 0
#define ESI 1
#define EDX 2
#define ECX 3
#define R8D 4
#define R9D 5

struct options opts;
/*
 * XXX this table is wrong, as u can see it has duplicates
 * which shouldn't be the same opcode :)
 */
struct branch_instr branch_table[64] = {
                        {"jo",  0x70}, 
                        {"jno", 0x71},  {"jb", 0x72},  {"jnae", 0x72},  {"jc", 0x72},  {"jnb", 0x73},
                        {"jae", 0x73},  {"jnc", 0x73}, {"jz", 0x74},    {"je", 0x74},  {"jnz", 0x75},
                        {"jne", 0x75},  {"jbe", 0x76}, {"jna", 0x76},   {"jnbe", 0x77}, {"ja", 0x77},
                        {"js",  0x78},  {"jns", 0x79}, {"jp", 0x7a},    {"jpe", 0x7a}, {"jnp", 0x7b},
                        {"jpo", 0x7b},  {"jl", 0x7c},  {"jnge", 0x7c},  {"jnl", 0x7d}, {"jge", 0x7d},
                        {"jle", 0x7e},  {"jng", 0x7e}, {"jnle", 0x7f},  {"jg", 0x7f},  {"jmp", 0xeb},
                        {"jmp", 0xe9},  {"jmpf", 0xea}, {NULL, 0}
                };



static struct branch_instr * search_branch_instr(uint8_t instr)
{
        int i;
        struct branch_instr *p, *ret;
        
        for (i = 0, p = branch_table; p->mnemonic != NULL; p++, i++) {
                if (instr == p->opcode)
                        return p;
        }
        
        return NULL;
}

char * get_fn_by_range(handle_t *h, unsigned long vaddr)
{
	int i;
	char *buf = heapAlloc(512);
	for (i = 0; i < h->lsc; i++) {
		if (vaddr >= h->lsyms[i].value && vaddr < h->lsyms[i].value + h->lsyms[i].size) {
			strncpy(buf, h->lsyms[i].name, sizeof(buf) - 3);
			strcat(buf, "()");
			return buf;
		}
	}
	return NULL;
}
static char * get_fn_name(handle_t *h, unsigned long vaddr)
{
	unsigned int i;

	for (i = 0; i < h->dsc; i++) {
		if (vaddr == h->dsyms[i].value) 
			return h->dsyms[i].name;
	}

	for (i = 0; i < h->lsc; i++) {
		if (vaddr == h->lsyms[i].value) 
			return h->lsyms[i].name;	 
	}
	
	return NULL;
}

static int fn_is_local(handle_t *h, const char *name)
{
	int i;
	for (i = 0; i < h->lsc; i++) 
		if (!strcmp(h->lsyms[i].name, name))
			return 1;
	for (i = 0; i < h->dsc; i++) 
		if (!strcmp(h->dsyms[i].name, name))
			return 0;
	if (!strncasecmp(name, "sub_", 4))
		return 1;
}

static int check_for_reg(char *op_str, int reg)
{
	char *p;
	char *rstr = alloca(16);
	int i;

	if ((p = strchr(op_str, ',')) == NULL) {
		if (op_str[0] != '0')
			strcpy(rstr, op_str);
	} else {
		for (i = 0, p = op_str; *p != ','; p++) 
			rstr[i++] = *p;
	}
	switch (reg) {
		case EDI:
			if (!strcasecmp(rstr, "edi"))
				return 1;
			else
			if (!strcasecmp(rstr, "rdi"))
				return 1;
			else
				return 0;
			break;
		case ESI:
			if (!strcasecmp(rstr, "esi"))
				return 1;
			else
			if (!strcasecmp(rstr, "rsi"))
				return 1;
			else
				return 0;
			break;
		case EDX:
			if (!strcasecmp(rstr, "edx"))
				return 1;
			else
			if (!strcasecmp(rstr, "rdx"))
				return 1;
			else
				return 0;
			break;
		 case ECX:
                        if (!strcasecmp(rstr, "ecx"))
                                return 1;
                        else
                        if (!strcasecmp(rstr, "rcx"))
                                return 1;
                        else
                                return 0;
                        break;
		case R8D:
			if (!strncasecmp(rstr, "r8", 2))
				return 1;
			else
				return 0;
			break;
		case R9D:
			if (!strncasecmp(rstr, "r9", 2))
				return 1;
			else
				return 0;
			break;
		default:
			break;
	}
	
	return 0;
}
		
	
int build_code_profile(handle_t *h)
{
	csh disas_handle;
 	cs_insn *insn;
 	size_t count;
	int mode = h->arch == 32 ? CS_MODE_32 : CS_MODE_64;
	ElfW(Off) offset = h->elf.entry - h->elf.textVaddr;
	uint8_t *code = &h->elf.mem[offset];
	struct branch_instr *branch_instr;
	unsigned long target_address, callsite;
	char *tmp;
	int c, argc;

 	if (cs_open(CS_ARCH_X86, CS_MODE_64, &disas_handle) != CS_ERR_OK)
		return -1;
	
	ElfW(Addr) dot_text = get_section_address(h, ".text");
	/*
	if (dot_text != 0) {
		size_t text_section_size = get_section_size(h, ".text");
		count = cs_disasm_ex(disas_handle, code, text_section_size, dot_text, 0, &insn);
	}
	else */
	count = cs_disasm_ex(disas_handle, code, h->elf.textSize, h->elf.entry, 0, &insn);
	if (count < 1) {
		fprintf(stderr, "Failed to disassemble code\n");
		return -1;
	}
	size_t j;
	for (j = 0; j < count; j++)  {
	//if (opts.debug) 
		/*
		 * Is the instruction a type of jmp?
		 */
		if ((branch_instr = search_branch_instr(insn[j].bytes[0])) != NULL) {
			/* Found a non-call branch instruction */
			h->branch_site[h->branch_count].branch_type = IMMEDIATE_JMP;
			h->branch_site[h->branch_count].branch.location = callsite = insn[j].address;
			h->branch_site[h->branch_count].branch.target_vaddr = target_address = strtoul(insn[j].op_str, NULL, 16);
			h->branch_site[h->branch_count].branch.target_offset = target_address - callsite - 1;
			h->branch_site[h->branch_count].branch.mnemonic = xstrdup(insn[j].mnemonic);
			if (opts.debug)
				printf("[+] Storing information for instruction: jmp %lx\n", target_address);
			h->branch_count++;
			continue;
		} 
		/*
		 * Is the instruction a call?
	    	 */
		if ((strncmp(insn[j].mnemonic, "call", 4) != 0)) 
			continue;

		/*
		 * Which type of call?
		 */
		switch(insn[j].bytes[0]) {
			
			case 0xE8:
				h->branch_site[h->branch_count].branch_type = IMMEDIATE_CALL;
				h->branch_site[h->branch_count].branch.location = callsite = insn[j].address;
				h->branch_site[h->branch_count].branch.target_vaddr = target_address = strtoul(insn[j].op_str, NULL, 16);
				h->branch_site[h->branch_count].branch.target_offset = target_address - callsite - sizeof(uint32_t);
				h->branch_site[h->branch_count].branch.ret_target = insn[j + 1].address; 
				h->branch_site[h->branch_count].branch.mnemonic = xstrdup(insn[j].mnemonic);
				if ((tmp = get_fn_name(h, target_address)) != NULL)
					h->branch_site[h->branch_count].branch.function = xstrdup(tmp);
				else	
					tmp = h->branch_site[h->branch_count].branch.function = xfmtstrdup("sub_%lx", target_address);
				if (fn_is_local(h, tmp))
					h->branch_site[h->branch_count].branch.calltype = LOCAL_CALL;
				else
					h->branch_site[h->branch_count].branch.calltype = PLT_CALL;
				int t;
				for (argc = 0, c = 0; c < MAX_ARGS; c++) {
					switch(c) {
						case 0:
							argc += check_for_reg(insn[j - (c + 1)].op_str, EDI);
							break;
						case 1:
							argc += check_for_reg(insn[j - (c + 1)].op_str, ESI);
							break;
						case 2:
							argc += check_for_reg(insn[j - (c + 1)].op_str, EDX);
							break;
						case 3:
							argc += check_for_reg(insn[j - (c + 1)].op_str, ECX);
							break;
						case 4:
							argc += check_for_reg(insn[j - (c + 1)].op_str, R8D);
							break;
						case 5:
							argc += check_for_reg(insn[j - (c + 1)].op_str, R9D);
							break;
					}
				} 
				/*
				 * We search to see if the same function has been called before, and if so
				 * is the argument count larger than what we just found? If so then use that
				 * argc value because it is likely correct over the one we just found (Which may
				 * be thrown off due to gcc optimizations
				 */
				
				h->branch_site[h->branch_count].branch.argc = argc;
				for (c = 0; c < h->branch_count; c++) {
					if (h->branch_site[c].branch_type != IMMEDIATE_CALL)
						continue;
					if (!strcmp(h->branch_site[c].branch.function, h->branch_site[h->branch_count].branch.function))
						if (h->branch_site[c].branch.argc > argc)
							h->branch_site[h->branch_count].branch.argc = h->branch_site[c].branch.argc;
				} 
				int r;
				int found_edi = 0;
				int found_esi = 0;
				int found_edx = 0;
				int found_ecx = 0;
				int found_r9 = 0;
				int found_r8 = 0;
				int k = 0;
				if (argc == 0) {
					/* Try aggressive arg resolution */
					for (c = 0; c < MAX_ARGS + 4; c++) {
						argc += r = check_for_reg(insn[j - (c + 1)].op_str, EDI);
						if (r != 0) {
							found_edi++;
							break;
						}	
					}	
					if (found_edi) {
						for (c = 0; c < MAX_ARGS + 4; c++) {
                                                        argc += r = check_for_reg(insn[j - (c + 1)].op_str, ESI);
                                                 	if (r != 0) {
								found_esi++;
								break;
							}       
                                                }
					}
					
				     	if (found_esi) {
                                        	for (c = 0; c < MAX_ARGS + 4; c++) {             
						   	argc += r = check_for_reg(insn[j - (c + 1)].op_str, EDX);
                                                        if (r != 0) {
                                                        	found_edx++;
                                                       		break;
							}
                                                }
					}
					
					if (found_edx) {
						for (c = 0; c < MAX_ARGS + 4; c++) {
                                                        argc += r = check_for_reg(insn[j - (c + 1)].op_str, ECX);
                                                        if (r != 0) {
								found_ecx++;
								break;
							}
                                                }
					}
					if (found_ecx) {
						for (c = 0; c < MAX_ARGS + 4; c++) {
							argc += r = check_for_reg(insn[j - (c + 1)].op_str, R8D);
							if (r != 0) {
								found_r8++;
								break;
							}
						}
					}
					if (found_r8) {
						for (c = 0; c < MAX_ARGS + 4; c++) {
                                                        argc += r = check_for_reg(insn[j - (c + 2)].op_str, R9D);
                                                        if (r != 0) {
                                                        	found_r9++;
                                                        	break;
							}
                                                } 

					}
					h->branch_site[h->branch_count].branch.argc = argc;
				}	
				h->branch_count++;	
                                break;

			case 0xFF: // not yet supported
				break;
		}
	}

	cs_free(insn, count);

	
}

