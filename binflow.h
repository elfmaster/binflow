#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <elf.h>
#include <sys/mman.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/stat.h>
#include <sys/reg.h>
#include <stdarg.h>
#include <pthread.h>
#include <link.h>


#include <linux/connector.h>
#include <linux/netlink.h>
#include <linux/cn_proc.h>
#include "capstone/capstone.h"

#define _GNU_SOURCE 
/*
 * For our color coding output
 */
#define WHITE "\x1B[0;37m"
#define RED  "\x1B[0;31m"
#define GREEN  "\x1B[1;32m"
#define YELLOW  "\x1B[0;33m"
#define CYAN  "\033[1;36m"      
#define BLUE "\x1b[1;34m"

#define DEFAULT_COLOR  "\x1B[0m"


/*
 * On 32bit systems should be set:
 * export FTRACE_ARCH=32
 */
#define FTRACE_ENV "FTRACE_ARCH"

#define MAX_ADDR_SPACE 256 
#define MAXSTR 512

#define TEXT_SPACE  0
#define DATA_SPACE  1
#define STACK_SPACE 2
#define HEAP_SPACE  3

#define CALLSTACK_DEPTH 0xf4240
#define MAX_BRANCHES 128000 

#define LOCAL_CALL 0
#define PLT_CALL 1

typedef struct breakpoint {
        unsigned long vaddr;
        long orig_code;
} breakpoint_t;

struct branch_instr {
        char *mnemonic;
        uint8_t opcode;
};

typedef struct x86_regs {
	unsigned long eax;
	unsigned long ebx;
	unsigned long ecx;
	unsigned long edx;
	unsigned long esi;
	unsigned long edi;
	unsigned long r8, r9, r10, r11, r12, r13, r14, r15;
	unsigned long eip;
	unsigned long esp;
} x86_regs_t;
        
#define BRANCH_INSTR_LEN_MAX 5

struct elf_section_range {
        char *sh_name;
        unsigned long sh_addr;
        unsigned int sh_size;
};


typedef struct elfdesc {
	uint8_t *mem;
	ElfW(Ehdr) *ehdr;
	ElfW(Phdr) *phdr;
	ElfW(Shdr) *shdr; 
	ElfW(Dyn) *dyn;
	ElfW(Addr) textVaddr;
	ElfW(Addr) dataVaddr;
	ElfW(Addr) dynVaddr;
	ElfW(Off) textOff;
	ElfW(Off) dataOff;
	ElfW(Off) dynOff;
	ElfW(Word) dynSize;
	ElfW(Word) textSize;
	ElfW(Word) dataSize;
	ElfW(Addr) entry;
	char *StringTable;
	char *symtab;
} elfdesc_t;	

struct address_pair {
	unsigned long va_min;
	unsigned long va_max;
};

struct address_space {
        unsigned long svaddr;
        unsigned long evaddr;
        unsigned int size;
        int count;
};

struct syms {
        char *name;
        unsigned long value;
	size_t size;
};

typedef enum {
	IMMEDIATE_CALL,
	INDIRECT_CALL,
	IMMEDIATE_JMP,
	INDIRECT_JMP,
	NEAR_RET,
	RET_TARGET
} branch_type_t;

typedef struct calldata {
                char *symname;
                char *string;
                unsigned long vaddr;
                unsigned long retaddr;
        //      unsigned int depth;
                breakpoint_t breakpoint;
} calldata_t;

typedef struct callstack {
        calldata_t *calldata;
        unsigned int depth; 
} callstack_t;

typedef struct branch_attr {
	char *function; // if its a call
	char *mnemonic;
	unsigned long orig_word; //orig instruction
	unsigned long orig_ret; //orig instr for rets only 
	unsigned long target_offset;
	unsigned long target_vaddr;
	unsigned long location;
	unsigned long ret_target; // if its a call
	unsigned long retsite; // if its a call
	int calltype;
	int argc; // # of args passed to function
} branch_attr_t;
	
typedef struct branch_site {
	branch_attr_t branch;
	branch_type_t branch_type;
} branch_site_t;

struct options {
        int verbose;
	int debug;
        int strings;
        int cflow;
        int elfdata;
        int ehframe;
        int attach;
        int arch;
	int threads;
};

#define MAX_SHDRS 256

typedef struct handle {
        char *path;
        char **args;
        uint8_t *map;
	unsigned long vdso;
	elfdesc_t elf;
        branch_site_t branch_site[MAX_BRANCHES]; // XXX change to linked list
	struct elf_section_range sh_range[MAX_SHDRS];
        struct syms *lsyms;
	struct syms *dsyms; //dynamic syms
        char *libnames[256];
        int lsc; //lsyms count
        int dsc; // dsyms count
        int lnc; //libnames count
        size_t branch_count;
	int shdr_count;
        int pid;
	int arch;
	struct address_space *addrspace;
} handle_t;

int validate_em_type(const char *);
uint8_t *get_section_data(handle_t *, const char *);
void locate_dynamic_segment(handle_t *);
int process_binary(handle_t *);
char * get_section_by_range(handle_t *, unsigned long);
char * get_path(int);
void get_address_space(struct address_space *, int, char *);
char *getstr(unsigned long, int);
char *get_fn_by_range(handle_t *, unsigned long);
void * heapAlloc(unsigned int);
char * xstrdup(const char *);
char * xfmtstrdup(char *, ...);
char * _strdupa(const char *);
int build_code_profile(handle_t *);
void xfree(void *);
unsigned long get_instruction_pointer(int);
ElfW(Addr) get_section_address(handle_t *, const char *);
size_t get_section_size(handle_t *, const char *);
/*
inline void set_breakpoint(handle_t *, void *, long *) __attribute__((always_inline));
inline void remove_breakpoint(handle_t *, void *, long) __attribute__((always_inline));
*/

