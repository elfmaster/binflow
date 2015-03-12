#include "binflow.h"

struct options opts;

char * get_section_by_range(handle_t *h, unsigned long vaddr)
{
        int i;

        for (i = 0; i < h->shdr_count; i++) {
                if (vaddr >= h->sh_range[i].sh_addr && vaddr <= h->sh_range[i].sh_addr + h->sh_range[i].sh_size)
                        return h->sh_range[i].sh_name;
        }
        
        return NULL;
}

ElfW(Addr) get_section_address(handle_t *h, const char *name)
{
	int i;
	ElfW(Ehdr) *ehdr = (ElfW(Ehdr) *)h->elf.ehdr;
	ElfW(Shdr) *shdr = (ElfW(Shdr) *)h->elf.shdr;
	char *StringTable = h->elf.StringTable;

	for (i = 0; i < ehdr->e_shnum; i++)
		if (!strcmp(&StringTable[shdr[i].sh_name], name))
			return shdr[i].sh_addr;
	return 0;
}

size_t get_section_size(handle_t *h, const char *name)
{
	int i;
        ElfW(Ehdr) *ehdr = (ElfW(Ehdr) *)h->elf.ehdr;
        ElfW(Shdr) *shdr = (ElfW(Shdr) *)h->elf.shdr;
        char *StringTable = h->elf.StringTable;

        for (i = 0; i < ehdr->e_shnum; i++)
                if (!strcmp(&StringTable[shdr[i].sh_name], name))
                        return shdr[i].sh_size;
        return 0;
}

void load_elf_section_range(handle_t *h)
{
        ElfW(Ehdr) *ehdr;
	ElfW(Shdr) *shdr;
        char *StringTable;
        int i;
	
	ehdr = (ElfW(Ehdr) *)h->elf.ehdr;
	shdr = (ElfW(Shdr) *)h->elf.shdr;
        h->shdr_count = 0;
	StringTable = h->elf.StringTable;
        for (i = 0; i < ehdr->e_shnum; i++) {
       		h->sh_range[i].sh_name = xstrdup(&StringTable[shdr[i].sh_name]);
		h->sh_range[i].sh_addr = shdr[i].sh_addr;
             	h->sh_range[i].sh_size = shdr[i].sh_size;
        	if (h->shdr_count == MAX_SHDRS)
                	break;
                h->shdr_count++;
      	}
}

/*
 * Build symbol table for .symtab and .dynsym
 */
void BuildSyms(handle_t *h)
{
        unsigned int i, j, k;
        char *SymStrTable;
        ElfW(Ehdr) *ehdr;
	ElfW(Shdr) *shdr;
	ElfW(Sym) *symtab;
        int st_type;
        
        h->lsc = 0;
        h->dsc = 0;
        ehdr = h->elf.ehdr;
        shdr = h->elf.shdr;
                
	for (i = 0; i < ehdr->e_shnum; i++) {
       		if (shdr[i].sh_type == SHT_SYMTAB || shdr[i].sh_type == SHT_DYNSYM) {
               		SymStrTable = (char *)&h->elf.mem[shdr[shdr[i].sh_link].sh_offset]; 
               		symtab = (ElfW(Sym) *)&h->elf.mem[shdr[i].sh_offset];
                      	for (j = 0; j < shdr[i].sh_size / sizeof(ElfW(Sym)); j++, symtab++) {
                       		st_type = ELF32_ST_TYPE(symtab->st_info);
                               	if (st_type != STT_FUNC)
                                	continue;
                                switch(shdr[i].sh_type) {
                                	case SHT_SYMTAB:
                                        	h->lsyms[h->lsc].name = xstrdup(&SymStrTable[symtab->st_name]);
                                              	h->lsyms[h->lsc].value = symtab->st_value;
						h->lsyms[h->lsc].size = symtab->st_size; 
                                               	h->lsc++;
                                               	break;
                                    	case SHT_DYNSYM:
                                      		h->dsyms[h->dsc].name = xstrdup(&SymStrTable[symtab->st_name]);
                                               	h->lsyms[h->dsc].value = symtab->st_value;
                                               	h->dsc++;
                                               	break;
                             	}
               		}
		}
	}
	h->elf.StringTable = (char *)&h->elf.mem[shdr[ehdr->e_shstrndx].sh_offset];
        for (i = 0; i < ehdr->e_shnum; i++) {
        	if (!strcmp(&h->elf.StringTable[shdr[i].sh_name], ".plt")) {
                	for (k = 0, j = 0; j < shdr[i].sh_size; j += 16) {
                        	if (j >= 16) 
                               		h->dsyms[k++].value = shdr[i].sh_addr + j;
                                
                        }
                        break;
             	}
     	}

}


char *get_dt_strtab_name(handle_t *h, int xset)
{
        static char *dyn_strtbl;

        if (!dyn_strtbl && !(dyn_strtbl = get_section_data(h, ".dynstr"))) 
                printf("[!] Could not locate .dynstr section\n");
  
        return dyn_strtbl + xset;
}

void parse_dynamic_dt_needed(handle_t *h)
{
        char *symstr;
        int i, n_entries;
	ElfW(Dyn) *dyn;

        locate_dynamic_segment(h);
        h->lnc = 0;

      	dyn = h->elf.dyn;
    	for (i = 0; dyn[i].d_tag != DT_NULL; i++) {
		if (dyn[i].d_tag == DT_NEEDED) {
               		symstr = get_dt_strtab_name(h, dyn[i].d_un.d_val);
                        h->libnames[h->lnc++] = (char *)xstrdup(symstr);
        	}
    	 }
}


uint8_t *get_section_data(handle_t *h, const char *section_name)
{
	char *StringTable = h->elf.StringTable;
	ElfW(Ehdr) *ehdr = h->elf.ehdr;
	ElfW(Shdr) *shdr = h->elf.shdr;
	int i;

	for (i = 0; i < ehdr->e_shnum; i++) {
		if (strcmp(&StringTable[shdr[i].sh_name], section_name) == 0) 
			return (uint8_t *)&h->elf.mem[shdr[i].sh_offset];
	}
	
	return NULL;
}

			
void locate_dynamic_segment(handle_t *h)
{
	h->elf.dyn = (ElfW(Dyn) *)&h->elf.mem[h->elf.dynOff];
}

int process_binary(handle_t *h)
{
	int fd, i;
	struct stat st;
	ElfW(Ehdr) *ehdr;
	ElfW(Phdr) *phdr;
	ElfW(Shdr) *shdr;
	uint8_t *mem;

	if ((fd = open(h->path, O_RDONLY)) < 0) {
		perror("open");
		return -1;
	}
	
	if (fstat(fd, &st) < 0) {
		perror("fstat");
		return -1;
	}

	mem = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (h->elf.mem == MAP_FAILED) {
		perror("mmap");
		return -1;
	}

	ehdr = (ElfW(Ehdr) *)mem;
	phdr = (ElfW(Phdr) *)&mem[ehdr->e_phoff];
	shdr = (ElfW(Shdr) *)&mem[ehdr->e_shoff];

	h->elf.StringTable = (char *)&mem[shdr[ehdr->e_shstrndx].sh_offset];
	
	h->elf.entry = ehdr->e_entry;
	
	h->map = mem;
	h->elf.mem = mem;
	h->elf.phdr = phdr;
	h->elf.ehdr = ehdr;
	h->elf.shdr = shdr;

	for (i = 0; i < ehdr->e_phnum; i++) {
		switch(phdr[i].p_type) {
			case PT_LOAD:
				switch(!(!phdr[i].p_offset)) { 
					case 0:
						h->elf.textVaddr = phdr[i].p_vaddr;
						h->elf.textSize = phdr[i].p_memsz;
						h->elf.textOff = phdr[i].p_offset;
						break;
					case 1:
						h->elf.dataVaddr = phdr[i].p_vaddr;
						h->elf.dataSize = phdr[i].p_memsz;
						h->elf.dataOff = phdr[i].p_offset;
						break;
				}
				break;
			case PT_DYNAMIC:
				h->elf.dynVaddr = phdr[i].p_vaddr;
				h->elf.dynSize = phdr[i].p_memsz;
				h->elf.dynOff = phdr[i].p_offset;
				break;
		}
	}
	
	BuildSyms(h);
	load_elf_section_range(h);
	if (build_code_profile(h) < 0) {
		fprintf(stderr, "Unable to build code profile for %s\n", h->path);
		return -1;
	}
	return 0;
}

int validate_em_type(const char *path)
{
        int fd;
        uint8_t *mem, *p;
        unsigned int value;
        Elf64_Ehdr *ehdr64;
        Elf32_Ehdr *ehdr32;

        if ((fd = open(path, O_RDONLY)) < 0) {
                fprintf(stderr, "Could not open %s: %s\n", path, strerror(errno));
                exit(-1);
        }
        
        mem = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, fd, 0);
        if (mem == MAP_FAILED) {
                perror("mmap");
                exit(-1);
        }
        switch (opts.arch) {
                case 32:
                        ehdr32 = (Elf32_Ehdr *)mem;
                        if (ehdr32->e_machine != EM_386)
                                return 0;
                        break;
                case 64:
                        ehdr64 = (Elf64_Ehdr *)mem;
                        if (ehdr64->e_machine != EM_X86_64 && ehdr64->e_machine != EM_IA_64)
                                return 0;
                        break;
        }
        return 1;
}
	
