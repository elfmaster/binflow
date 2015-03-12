#include "binflow.h"
#define M_OFFSETOF(STRUCT, ELEMENT) \
	(unsigned long) &((STRUCT *)NULL)->ELEMENT;

struct options opts;

int get_ptrace_regs_portable(handle_t *h, x86_regs_t *regs, struct user_regs_struct *pt_reg)
{
	if (ptrace(PTRACE_GETREGS, h->pid, NULL, pt_reg) < 0) {
		perror("PTRACE_GETREGS");
		return -1;
	}

#ifdef __x86_64__
	regs->esp = pt_reg->rsp;
	regs->eip = pt_reg->rip;
	regs->eax = pt_reg->rax;
	regs->ebx = pt_reg->rbx;
	regs->ecx = pt_reg->rcx;
	regs->edx = pt_reg->rdx;
	regs->esi = pt_reg->rsi;
	regs->edi = pt_reg->rdi;
#else
	regs->esp = pt_reg->esp;
	regs->eip = pt_reg->eip;
	regs->eax = pt_reg->eax;
	regs->ebx = pt_reg->ebx;
	regs->ecx = pt_reg->ecx;
	regs->edx = pt_reg->edx;
	regs->esi = pt_reg->esi;
	regs->edi = pt_reg->edi;
#endif
	return 0;
}

int set_ptrace_eip_portable(handle_t *h, struct user_regs_struct *pt_regs, unsigned long eip)
{
#ifdef __x86_64__
	pt_regs->rip = eip;
#else
	pt_regs->eip = eip;
#endif
	if (ptrace(PTRACE_SETREGS, h->pid, NULL, pt_regs) < 0) {
		perror("PTRACE_GETREGS");
		return -1;
	}
	return 0;
}

	
int pid_write(int pid, void *dest, const void *src, size_t len)
{
        size_t rem = len % sizeof(void *);
        size_t quot = len / sizeof(void *);
        unsigned char *s = (unsigned char *) src;
        unsigned char *d = (unsigned char *) dest;
        
        while (quot-- != 0) {
                if ( ptrace(PTRACE_POKEDATA, pid, d, *(void **)s) == -1 )
                        goto out_error;
                s += sizeof(void *);
                d += sizeof(void *);
        }

        if (rem != 0) {
                long w;
                unsigned char *wp = (unsigned char *)&w;

                w = ptrace(PTRACE_PEEKDATA, pid, d, NULL);
                if (w == -1 && errno != 0) {
                        d -= sizeof(void *) - rem;

                        w = ptrace(PTRACE_PEEKDATA, pid, d, NULL);
                        if (w == -1 && errno != 0)
                                goto out_error;

                        wp += sizeof(void *) - rem;
                }

                while (rem-- != 0)
                        wp[rem] = s[rem];

                if (ptrace(PTRACE_POKEDATA, pid, (void *)d, (void *)w) == -1)
                        goto out_error;
        }

        return 0;

out_error:
        fprintf(stderr, "pid_write() failed, pid: %d: %s\n", pid, strerror(errno));
        return -1;
}

	
int pid_read(int pid, void *dst, const void *src, size_t len)
{

        int sz = len / sizeof(void *);
        unsigned char *s = (unsigned char *)src;
        unsigned char *d = (unsigned char *)dst;
        long word;
        
        while (sz-- != 0) {
                word = ptrace(PTRACE_PEEKTEXT, pid, s, NULL);
                if (word == -1 && errno) 
                        return -1;
         
               *(long *)d = word;
                s += sizeof(long);
                d += sizeof(long);
        }
        
        return 0;
}

static char * get_pointer_range_str(handle_t *h, unsigned long addr)
{	
	int j;
	char *s;

	for (j = 0; j < 4; j++) {
        	if (addr >= h->addrspace[j].svaddr && addr <= h->addrspace[j].evaddr) 
			switch(j) {
				case TEXT_SPACE:
					if (opts.strings) {
						s = getstr(addr, h->pid);
						if (s != NULL)
							return s;
						else
							return xfmtstrdup("(text_t *)%lx", addr);
					}
					return xfmtstrdup("(text_t *)");
				case HEAP_SPACE:
					 if (opts.strings) {
                                                s = getstr(addr, h->pid);
                                                if (s != NULL)
                                                        return s;
						else
							return xfmtstrdup("(heap_t *)%lx", addr);
                                        }
					return xfmtstrdup("(heap_t *)");
				case DATA_SPACE:
					 if (opts.strings) {
                                                s = getstr(addr, h->pid);
                                                if (s != NULL)
                                                        return s;
						else
							return xfmtstrdup("(data_t *)%lx", addr);
                                        }
					return xfmtstrdup("(data_t *)");
				case STACK_SPACE:
					 if (opts.strings) {
                                                s = getstr(addr, h->pid);
                                                if (s != NULL)
                                                        return s;
						else
							return xfmtstrdup("(stack_t *)%lx", addr);
                                        }
					return xfmtstrdup("(stack_t *)");
			}
	}

	return NULL;
}
/*
 * Do not let the unsafe strcpy/strcat 
 * in this crazy function scare you. Everything
 * is pre-allocated and nothing will ever exceed
 * the sizes to create an overflow condition.
 */
char * build_arg_string(handle_t *h, branch_site_t *branch)
{
	char *str = (char *)heapAlloc(1024);
	char *tmp = (char *)alloca(512);
	char *args[6];
	char *ptr_range, *p;
	struct user_regs_struct regs;
	int is_str = 0;
	ptrace(PTRACE_GETREGS, h->pid, NULL, &regs);
		
	switch(branch->branch.argc) {
		case 0:
			strcpy(str, "(");
			break;
		case 1:
			sprintf(tmp, "0x%llx", regs.rdi);
			ptr_range = get_pointer_range_str(h, regs.rdi);
			if (ptr_range == NULL)
				args[0] = xstrdup(tmp);
			else {
				if (opts.strings) 
					args[0] = xfmtstrdup("%s", ptr_range);
				else
					args[0] = xfmtstrdup("%s%s", ptr_range, tmp);
			}
			xfree(ptr_range);
			strcpy(str, "(");
			strcat(str, args[0]);
			if ((p = strchr(str, ',')) != NULL) 
				*p = '\0'; // , is added by getstr() 
			free(args[0]);
			break;
		case 2:
			sprintf(tmp, "0x%llx", regs.rdi);
			ptr_range = get_pointer_range_str(h, regs.rdi);
			if (ptr_range == NULL)
				args[0] = xstrdup(tmp);
			else {
				if (opts.strings)
					args[0] = xfmtstrdup("%s", ptr_range);
				else
					args[0] = xfmtstrdup("%s%s", ptr_range, tmp);
			}
			xfree(ptr_range);
			strcpy(str, "(");
			strcat(str, args[0]);
			sprintf(tmp, "0x%llx", regs.rsi);
			ptr_range = get_pointer_range_str(h, regs.rsi);
			if (ptr_range == NULL)
				args[1] = xstrdup(tmp);
			else {
				if (opts.strings)
					args[1] = xfmtstrdup("%s", ptr_range);
				else
					args[1] = xfmtstrdup("%s%s", ptr_range, tmp);
			}
			xfree(ptr_range);
			strcat(str, ", ");
			if ((p = strchr(args[1], ',')) != NULL)
				*p = '\0'; 
			strcat(str, args[1]);
			free(args[0]);
			free(args[1]);
			break;
		case 3:
		        sprintf(tmp, "0x%llx", regs.rdi);
                        ptr_range = get_pointer_range_str(h, regs.rdi);
                        if (ptr_range == NULL)
                                args[0] = xstrdup(tmp);
                        else {
				if (opts.strings)
					args[0] = xfmtstrdup("%s", ptr_range);
				else
                                	args[0] = xfmtstrdup("%s%s", ptr_range, tmp);
			}
                        xfree(ptr_range);
                        strcpy(str, "(");
			strcat(str, args[0]);
                        sprintf(tmp, "0x%llx", regs.rsi);
			ptr_range = get_pointer_range_str(h, regs.rsi);
                        if (ptr_range == NULL)
                                args[1] = xstrdup(tmp);
                        else {
				if (opts.strings)
					args[1] = xfmtstrdup("%s", ptr_range);
				else
                                	args[1] = xfmtstrdup("%s%s", ptr_range, tmp);
			}
                        xfree(ptr_range);
                        strcat(str, ", ");
                        strcat(str, args[1]);
			sprintf(tmp, "0x%llx", regs.rdx);
			ptr_range = get_pointer_range_str(h, regs.rdx);
			if (ptr_range == NULL)
				args[2] = xstrdup(tmp);
			else {
				if (opts.strings)
					args[2] = xfmtstrdup("%s", ptr_range);
				else
					args[2] = xfmtstrdup("%s%s", ptr_range, tmp);
			}
			xfree(ptr_range);
			strcat(str, ", ");
			if ((p = strchr(args[2], ',')) != NULL)
				*p = '\0';
			strcat(str, args[2]);
			free(args[0]);
			free(args[1]);
			free(args[2]);
			break;
		case 4:
		        sprintf(tmp, "0x%llx", regs.rdi);
                        ptr_range = get_pointer_range_str(h, regs.rdi);
                        if (ptr_range == NULL)
                                args[0] = xstrdup(tmp);
                        else {
				if (opts.strings)
					args[0] = xfmtstrdup("%s", ptr_range);
				else
                              		args[0] = xfmtstrdup("%s%s", ptr_range, tmp);
			}
                        xfree(ptr_range);
			strcpy(str, "(");
			strcat(str, args[0]);
                        sprintf(tmp, "0x%llx", regs.rsi);
			ptr_range = get_pointer_range_str(h, regs.rsi);
                        if (ptr_range == NULL)
                                args[1] = xstrdup(tmp);
                        else {
				if (opts.strings)
					args[1] = xfmtstrdup("%s", ptr_range);
				else
                                	args[1] = xfmtstrdup("%s%s", ptr_range, tmp);
			}
                        xfree(ptr_range);
			strcat(str, ", ");
			strcat(str, args[1]);
                        sprintf(tmp, "0x%llx", regs.rdx);
                        ptr_range = get_pointer_range_str(h, regs.rdx);
                        if (ptr_range == NULL)
                                args[2] = xstrdup(tmp);
                        else {
				if (opts.strings)
					args[2] = xfmtstrdup("%s", ptr_range);
				else
                                	args[2] = xfmtstrdup("%s%s", ptr_range, tmp);
			}
                        free(ptr_range);
                        strcat(str, ", ");
                        strcat(str, args[2]);
			sprintf(tmp, "0x%llx", regs.rdx);
			ptr_range = get_pointer_range_str(h, regs.rcx);
			if (ptr_range == NULL)
				args[3] = xstrdup(tmp);
			else {
				if (opts.strings)
					args[3] = xfmtstrdup("%s", ptr_range);
				else
					args[3] = xfmtstrdup("%s%s", ptr_range, tmp);
			}
			xfree(ptr_range);
			strcat(str, ", ");
			if ((p = strchr(args[3], ',')) != NULL)
				*p = '\0';
			strcat(str, args[3]);
			free(args[0]);
			free(args[1]);
			free(args[2]);
			free(args[3]);
			//sprintf(str, "(0x%llx, 0x%llx, 0x%llx, 0x%llx)", regs.rdi, regs.rsi, regs.rdx, regs.rcx);
			break;
		case 5:
			sprintf(tmp, "0x%llx", regs.rdi);
                        ptr_range = get_pointer_range_str(h, regs.rdi);
                        if (ptr_range == NULL)
                                args[0] = xstrdup(tmp);
                        else {
				if (opts.strings)
                                	args[0] = xfmtstrdup("%s", ptr_range);
				else
					args[0] = xfmtstrdup("%s%s", ptr_range, tmp);
			}
                        xfree(ptr_range);
                        strcpy(str, "(");
                        strcat(str, args[0]);
                        sprintf(tmp, "0x%llx", regs.rsi);
                        ptr_range = get_pointer_range_str(h, regs.rsi);
                        if (ptr_range == NULL)
                                args[1] = xstrdup(tmp);
                        else {
				if (opts.strings)
					args[1] = xfmtstrdup("%s", ptr_range);
				else
                                	args[1] = xfmtstrdup("%s%s", ptr_range, tmp);
			}
                        xfree(ptr_range);
                        strcat(str, ", ");
                        strcat(str, args[1]);
                        sprintf(tmp, "0x%llx", regs.rdx);
                        ptr_range = get_pointer_range_str(h, regs.rdx);
                        if (ptr_range == NULL)
                                args[2] = xstrdup(tmp);
                        else {
				if (opts.strings)
					args[2] = xfmtstrdup("%s", ptr_range);
				else
                                	args[2] = xfmtstrdup("%s%s", ptr_range, tmp);
			}
                        xfree(ptr_range);
                        strcat(str, ", ");
                        strcat(str, args[2]);
                        sprintf(tmp, "0x%llx", regs.rcx);
                        ptr_range = get_pointer_range_str(h, regs.rcx);
                        if (ptr_range == NULL)
                                args[3] = xstrdup(tmp);
                        else {
				if (opts.strings)
					args[3] = xfmtstrdup("%s", ptr_range);
				else
                                	args[3] = xfmtstrdup("%s%s", ptr_range, tmp);
			}
                        xfree(ptr_range);
                        strcat(str, ", ");
                        strcat(str, args[3]);
			sprintf(tmp, "0x%llx", regs.r9);
                        ptr_range = get_pointer_range_str(h, regs.r9);
                        if (ptr_range == NULL)
                                args[4] = xstrdup(tmp);
                        else {
				if (opts.strings)
                                	args[4] = xfmtstrdup("%s", ptr_range);
				else
					args[4] = xfmtstrdup("%s%s", ptr_range, tmp);
			}
                        xfree(ptr_range);
                        strcat(str, ", ");
                        if ((p = strchr(args[4], ',')) != NULL)
				*p = '\0';
			strcat(str, args[4]);
			free(args[0]);
                        free(args[1]);
                        free(args[2]);
                        free(args[3]);
			free(args[4]);
			break;
		case 6:
			sprintf(tmp, "0x%llx", regs.rdi);
                        ptr_range = get_pointer_range_str(h, regs.rdi);
                        if (ptr_range == NULL)
                                args[0] = xstrdup(tmp);
                        else {
				if (opts.strings)
					args[0] = xfmtstrdup("%s", ptr_range);
				else
                                	args[0] = xfmtstrdup("%s%s", ptr_range, tmp);
                        }
			xfree(ptr_range);
                        strcpy(str, "(");
                        strcat(str, args[0]);
                        sprintf(tmp, "0x%llx", regs.rsi);
                        ptr_range = get_pointer_range_str(h, regs.rsi);
                        if (ptr_range == NULL)
                                args[1] = xstrdup(tmp);
                        else {
				if (opts.strings)
					args[1] = xfmtstrdup("%s", ptr_range);
				else
                                	args[1] = xfmtstrdup("%s%s", ptr_range, tmp);
                        }
			xfree(ptr_range);
                        strcat(str, ", ");
                        strcat(str, args[1]);
                        sprintf(tmp, "0x%llx", regs.rdx);
                        ptr_range = get_pointer_range_str(h, regs.rdx);
                        if (ptr_range == NULL)
                                args[2] = xstrdup(tmp);
                        else {
				if (opts.strings)
					args[2] = xfmtstrdup("%s", ptr_range);
				else
                                	args[2] = xfmtstrdup("%s%s", ptr_range, tmp);
			}
                        xfree(ptr_range);
                        strcat(str, ", ");
                        strcat(str, args[2]);
                        sprintf(tmp, "0x%llx", regs.rcx);
                        ptr_range = get_pointer_range_str(h, regs.rcx);
                        if (ptr_range == NULL)
                                args[3] = xstrdup(tmp);
                        else {
				if (opts.strings)
					args[3] = xfmtstrdup("%s", ptr_range);
				else
                                	args[3] = xfmtstrdup("%s%s", ptr_range, tmp);
                        }
			xfree(ptr_range);
                        strcat(str, ", ");
                        strcat(str, args[3]);
                        sprintf(tmp, "0x%llx", regs.r9);
                        ptr_range = get_pointer_range_str(h, regs.r9);
                        if (ptr_range == NULL)
                                args[4] = xstrdup(tmp);
                        else {
				if (opts.strings)
					args[4] = xfmtstrdup("%s", ptr_range);
				else
                                	args[4] = xfmtstrdup("%s%s", ptr_range, tmp);
                        }
			xfree(ptr_range);
			strcat(str, ", ");
                        strcat(str, args[4]);
			sprintf(tmp, "0x%llx", regs.r8);
                        ptr_range = get_pointer_range_str(h, regs.r8);
                        if (ptr_range == NULL)
                                args[5] = xstrdup(tmp);
                        else {
				if (opts.strings)
                                	args[5] = xfmtstrdup("%s", ptr_range);
				else	
					args[5] = xfmtstrdup("%s%s", ptr_range, tmp);
                        }
			xfree(ptr_range);
                        strcat(str, ", ");
                        if ((p = strchr(args[5], ',')) != NULL)
				*p = '\0';
			strcat(str, args[5]);
		        free(args[0]);
                        free(args[1]);
                        free(args[2]);
                        free(args[3]);
			free(args[4]);
			free(args[5]);
			break;
	}
	strcat(str, ")");
	return str;
}

char *getstr(unsigned long addr, int pid)
{       
        int i, j, c;
        uint8_t buf[sizeof(long)];
        char *string = (char *)heapAlloc(256);
        unsigned long vaddr;
        
        string[0] = '"';
        for (c = 1, i = 0; i < 256; i += sizeof(long)) {
                vaddr = addr + i;

                if (pid_read(pid, buf, (void *)vaddr, sizeof(long)) == -1) {
                        fprintf(stderr, "pid_read() failed: %s <0x%lx>\n", strerror(errno), vaddr);
                        exit(-1);
                }
 
                for (j = 0; j < sizeof(long); j++) {

                        if (buf[j] == '\n') {
                                string[c++] = '\\';
                                string[c++] = 'n';
                                continue;
                        }
                        if (buf[j] == '\t') {
                                string[c++] = '\\';
                                string[c++] = 't';
                                continue;
                        }

                        if (buf[j] != '\0' && isascii(buf[j]))
                                string[c++] = buf[j];
                        else {
				if (j == 1)
					return NULL;
                                goto out;
			}
                }
        }
        
out:
        string[c++] = '"';
	//string[c++] = ',';
        string[c] = '\0';

        return string;  

}

void set_breakpoint (int pid, unsigned long bp, unsigned long *backup)
{
	unsigned long bpinstr;
	*backup = ptrace(PTRACE_PEEKDATA, pid, bp, 0);
	bpinstr = (*backup & ~0xff) | 0xcc;
	pid_write(pid, (void *)bp, (void *)&bpinstr, sizeof(long));
}

void remove_breakpoint_and_step(int pid, unsigned long bp, unsigned long backup) 
{
	int status, i;
	FILE *fd;
	unsigned int eip_offset, ip;
	unsigned long addr = bp; // addr = breakpoint addr
	struct user_regs_struct pt_reg;
	siginfo_t siginfo;
	char dbuf[16];
#ifdef __x86_64__
        eip_offset = M_OFFSETOF(struct user_regs_struct, rip);
#else
        eip_offset = m_OFFSETOF(struct user_regs_struct, eip);
#endif
	pid_write(pid, (void *)addr, (void *)&backup, sizeof(long));
	
	//pid_read(pid, dbuf, addr, sizeof(long));
	/* now we set the process' instruction pointer back to the start of the original instruction */
	long ret = ptrace(PTRACE_POKEUSER, pid, eip_offset, addr);
	if (ret < 0) {
		perror("PTRACE_POKEUSER");
		exit(-1);
	}

	if (ptrace(PTRACE_SINGLESTEP, pid, 0, 0) < 0) {
		perror("PTRACE_SINGLESTEP");
		exit(-1);
	}
	wait(&status);
	//waitpid(pid, &status, WUNTRACED|WCONTINUED);
}

unsigned long get_instruction_pointer(int pid)
{
        unsigned int eip_offset; // offset of rip in struct user_regs_struct
	unsigned long eip;

#ifdef __x86_64__
        eip_offset = M_OFFSETOF(struct user_regs_struct, rip);
#else
        eip_offset = m_OFFSETOF(struct user_regs_struct, eip);
#endif

        eip = ptrace(PTRACE_PEEKUSER, pid, eip_offset);

	return eip;
}

unsigned long get_top_of_stack(handle_t *h)
{
	unsigned int esp_offset;
	unsigned long esp;
	int pid = h->pid;
	struct user_regs_struct pt_reg;
	unsigned long retval;
	int i;

	ptrace(PTRACE_GETREGS, h->pid, NULL, &pt_reg);
	pid_read(pid, (void *)&retval, (void *)pt_reg.rsp, 8);
	return retval; //ptrace(PTRACE_PEEKDATA, pid, (void *)pt_reg.rsp + 500, NULL);
}

long lookup_breakpoint_origval(handle_t *h, unsigned long addr)
{
	unsigned int i;
	for (i = 0; i < h->branch_count; i++) {
		if (h->branch_site[i].branch.location == addr)
			return h->branch_site[i].branch.orig_word;
	}
	return 0;

}

branch_site_t * lookup_breakpoint_branch(handle_t *h, unsigned long addr)
{
        unsigned int i;
        for (i = 0; i < h->branch_count; i++) {
                if (h->branch_site[i].branch.location == addr)
                        return &h->branch_site[i];
        }
        return NULL;

}


int instrument_process(handle_t *h)
{
	size_t i;
	for (i = 0; i < h->branch_count; i++) {
		switch(h->branch_site[i].branch_type) {
			case IMMEDIATE_CALL:
				if (opts.debug)
					printf("[+] Setting breakpoint on immediate 'call %lx' instruction: %lx\n", 
						h->branch_site[i].branch.target_vaddr, h->branch_site[i].branch.location);
				set_breakpoint(h->pid, h->branch_site[i].branch.location, &h->branch_site[i].branch.orig_word);
				break;
			case INDIRECT_CALL:
				break;
			case RET_TARGET:
				if (opts.debug)
					printf("[+] Setting breakpoint on ret target at %lx\n", h->branch_site[i].branch.location);
				set_breakpoint(h->pid, h->branch_site[i].branch.location, &h->branch_site[i].branch.orig_word);
				break;
			case IMMEDIATE_JMP:
				if (opts.debug)
                                        printf("[+] Setting breakpoint on immediate jmp instruction: %lx\n", h->branch_site[i].branch.location);
                                set_breakpoint(h->pid, h->branch_site[i].branch.location, &h->branch_site[i].branch.orig_word);
				break;
			case INDIRECT_JMP:
				break;
		}
	}


}

int process_breakpoint_location(handle_t *h, unsigned long bpaddr)
{
	char *shdr1, *shdr2, *argstr, *f1, *f2;
	unsigned long vaddr;
	branch_site_t *branch_site = lookup_breakpoint_branch(h, bpaddr);
	
	if (branch_site == NULL) {
		fprintf(stderr, "[!] failed to locate branch data for breakpoint at %lx\n", bpaddr);
		return -1;
	}
	switch(branch_site->branch_type) {
		case IMMEDIATE_CALL:
			switch(branch_site->branch.calltype) {
				case LOCAL_CALL:
					/*
					 * This may not be a call but a ret_target which is indexed in as a call
					 */
					argstr = build_arg_string(h, branch_site);
					printf("%sLOCAL_call@0x%lx%s: %s%s\n", GREEN, bpaddr, WHITE, branch_site->branch.function, argstr);
					free (argstr);
					break;
				case PLT_CALL:
					argstr = build_arg_string(h, branch_site);
					printf("%sPLT_call@0x%lx:%s %s%s\n", GREEN, bpaddr, WHITE, branch_site->branch.function, argstr);
					free(argstr);
					break;
			}
			break;
		case IMMEDIATE_JMP:
			if (!opts.cflow)
				break;
			shdr1 = get_section_by_range(h, bpaddr);
			if (shdr1 == NULL)
				shdr1 = (char *)_strdupa("<unknown section>");
			shdr2 = get_section_by_range(h, branch_site->branch.target_vaddr);
			if (shdr2 == NULL)
				shdr2 = (char *)_strdupa("<unknown_section>");
			if (!strcmp(shdr1, ".text") && !strcmp(shdr2, ".text")) {
				f1 = get_fn_by_range(h, bpaddr);
				f2 = get_fn_by_range(h, branch_site->branch.target_vaddr);
				if (f1 == NULL || f2 == NULL) {
					f1 = xstrdup(shdr1); // replace func names with shdr names if they can't be found
					f2 = xstrdup(shdr2); 
				}
			        printf("%s(CONTROL FLOW CHANGE [%s%s%s]):%s Jump from %s %lx to %s %lx\n", 
				CYAN, BLUE, branch_site->branch.mnemonic, CYAN, WHITE, 
                                f1, bpaddr, f2, branch_site->branch.target_vaddr);
				free(f1);
				free(f2);

			} else
				/* If we are in any section other than .text then we print the
				 * src and dst section name instead of the function name.
				 */
				printf("%s(CONTROL FLOW CHANGE [%s%s%s]):%s Jump from %s %lx into %s %lx\n", 
				CYAN, BLUE, branch_site->branch.mnemonic, CYAN, WHITE, 
				shdr1, bpaddr, shdr2, branch_site->branch.target_vaddr);
			break;
	}
	return 0;
}


int examine_process(handle_t *h)
{
	unsigned int i, j;
	h->addrspace = (struct address_space *)heapAlloc(sizeof(struct address_space) * MAX_ADDR_SPACE); 
        struct user_regs_struct pt_regs;
	x86_regs_t x86_regs;
	int status;
	unsigned int eip_offset; 
	unsigned long orig_word;
	unsigned long bpaddr;
	unsigned long null;
	siginfo_t siginfo;
	char buf[16];

#ifdef __x86_64__
	eip_offset = M_OFFSETOF(struct user_regs_struct, rip);
#else
	eip_offset = m_OFFSETOF(struct user_regs_struct, eip);
#endif
	
	get_address_space((struct address_space *)h->addrspace, h->pid, h->path);
	
	if (opts.verbose || opts.debug)
		printf("[+] Tracing process %d\n", h->pid);
	
	if (opts.elfdata) {
        	printf("[+] Printing Symbol Information:\n\n");
                for (i = 0; i < h->lsc; i++) {
                        if (h->lsyms[i].name == NULL)
                                printf("UNKNOWN: 0x%lx\n", h->lsyms[i].value);
                        else
                                printf("%s 0x%lx\n", h->lsyms[i].name, h->lsyms[i].value);
                }
                for (i = 0; i < h->dsc; i++) {
                        if (h->dsyms[i].name == NULL)
                                printf("UNKNOWN: 0x%lx\n", h->dsyms[i].value);
                        else
                                printf("%s 0x%lx\n", h->dsyms[i].name, h->dsyms[i].value);
                }
                
                printf("\n[+] Printing shared library dependencies:\n\n");
                
                parse_dynamic_dt_needed(h);
                for (i = 0; i < h->lnc; i++) {
                        printf("[%d]\t%s\n", i + 1, h->libnames[i]);
                }
        }
	
		int newpid;
		int special;
do_trace:
		special = 0;
  		if (ptrace(PTRACE_CONT, h->pid, NULL, NULL) < 0) {
                	perror("PTRACE_CONT");
                	return -1;
        	}
		wait(&status);
		
		if (WIFEXITED(status)) 
			goto done;
		
		if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) { 
			if ((status >> 8) == (SIGTRAP | PTRACE_EVENT_FORK << 8)) {
				special++;
			   	ptrace(PTRACE_GETEVENTMSG, h->pid, NULL, (void *)&newpid);
				printf("New process forked: %d\n", newpid);
			} else
			if ((status >> 8) == (SIGTRAP | PTRACE_EVENT_CLONE << 8)) {
				special++;
				ptrace(PTRACE_GETEVENTMSG, h->pid, NULL, (void *)&newpid);
				printf("New process cloned: %d\n", newpid);
			} else
			if ((status >> 8) == (SIGTRAP | PTRACE_EVENT_EXIT << 8)) {
				special++;
				ptrace(PTRACE_GETEVENTMSG, h->pid, NULL, (void *)&newpid);
				printf("Dying pid: %d\n", newpid);
			}
			// continue back tracing
			if (special)
				goto do_trace;

			char dbuf[16];
			/* Regular SIGTRAP? */
			bpaddr = get_instruction_pointer(h->pid); // will be at bpaddr + 1
                        orig_word = lookup_breakpoint_origval(h, bpaddr - 1); 
                        if (orig_word == 0)
                        	goto do_trace;
			process_breakpoint_location(h, bpaddr - 1);
                        remove_breakpoint_and_step(h->pid, bpaddr - 1, orig_word);
			set_breakpoint(h->pid, bpaddr - 1, &null); 
			goto do_trace;
		}
		goto do_trace;

done:
	return 0;
}

