#include "binflow.h"

struct options opts;

void usage(void)
{
	
	fprintf(stderr, "Usage: binflow [-secftvd] [-b <binary> [arg0,arg1,...]  [-p <pid>]\n");
	fprintf(stderr, "[-b]	Specify binary\n"
			"[-p]	Specify process ID\n"
			"[-s]	Show strings\n" 
			"[-e]	Extensive ELF info\n"
			"[-c]	Control flow analysis (Every branch instruction)\n"
			"[-f]	eh_frame (Exception handling frame) for function identification\n"
			"[-t]	Thread (clone/fork) support\n"
			"[-v]	Verbose output\n"
			"[-d]	Debugging output\n\n"
			"Examples:\n"
			"binflow -sc -b /bin/ls -R\n"
			"binflow -fe -p 996\n"); 
        exit(0);
}

int parse_sub_args(char **argv, int argc, char ***args, char *argv0)
{
	int tokens = 0, i;
	
	if ((*args = calloc(argc + 2, sizeof(char *))) == NULL)
		tokens = -1;
	*((*args) + 0) = xstrdup(argv0);
	for (i = 1; i <= argc; i++, tokens++) { 
		*((*args) + i) = xstrdup(argv[i - 1]);	
	}
	*((*args) + i) = NULL;
	return tokens + 1;
}

int main(int argc, char **argv, char **envp)
{
	handle_t *handle;
	char *token = NULL, **args;
	int ac, i, status, ret;
	pid_t pid;
	long ptraceOpts;
	char *argv0;

	if (argc < 3) 
		usage();
	if (argv[1][0] != '-') 
		usage(); 
	
	/*
	 * XXX handle is huge because of branch_site (Which is a massive array)
	 * so we must use heap. In the future move branch_site from array to 
	 * list or tree for fast lookup.
	 */
	handle = (handle_t *)heapAlloc(sizeof(handle_t));
	
	memset((void *)handle, 0, sizeof(handle_t));
	memset((void *)&opts, 0, sizeof(opts));
	
	if (argv[1][0] != '-')
		usage();
	if (argv[1][1] != 'b' && argv[1][1] != 'p') {
                for (token = (argv[1] + 1); *token != '\0'; token++) {
                        switch(*token) {
                                case 'v':
                                        opts.verbose++;
                                        break;
                                case 's':
                                        opts.strings++;
                                        break;
                                case 'c':
                                        opts.cflow++;
                                        break;
                                case 'e':
                                        opts.elfdata++;
                                        break;
                                case 'f':
                                        opts.ehframe++;
                                        break;
                                case 't':
                                        opts.threads++;
                                        break;
                                case 'd':
                                        opts.debug++;
                                        break;
                                default:
                                        printf("Unknown option: '%c'\n", *token);
                                        usage();	
			}
		}
		if (argc < 4)
			usage();
		if (argv[2][0] != '-')
			usage();
		if (argv[2][1] == 'b')
			handle->path = strdup(argv[3]);
		else
		if (argv[2][1] == 'p')
			handle->pid = atoi(argv[3]);
		else
			usage();
		argv0 = handle->path ? xstrdup(argv[3]) : get_path(handle->pid);
		ac = parse_sub_args(&argv[4], argc - 4, &handle->args, argv0);	
	} else {

		if (argv[1][0] != '-')
			usage();
		if (argv[1][1] == 'b')
			handle->path = strdup(argv[2]);
		else
		if (argv[1][1] == 'p')
			handle->pid = atoi(argv[2]);
		else
			usage();
		argv0 = handle->path ? xstrdup(argv[2]) : get_path(handle->pid);
		ac = parse_sub_args(&argv[3], argc - 3, &handle->args, argv0);
	}	
	
	
	switch(__ELF_NATIVE_CLASS) {
		case 32:
			opts.arch = 32;
			break;
		case 64:
			opts.arch = 64;
			break;
		default:
			fprintf(stderr, "[!] Unsupported architecture: %d\n", __ELF_NATIVE_CLASS);
			exit(0);
	}
	
	handle->arch = opts.arch;
	pid = handle->pid;
	if (pid) {
		if (opts.verbose)
			printf("[+] Attaching to pid: %d\n", pid);
		opts.attach++;
		handle->path = get_path(handle->pid);
	}	
	
        if (!validate_em_type(handle->path)) {
        	printf("[!] ELF Architecture is set to %d, the target %s is not the same architecture\n", opts.arch, handle->path);
                exit(-1);
        }

	/*
	 * process_binary() will create the mapping of branch instructions
	 * and layout of the executable, so that we can instrument it before
	 * execution.
	 */
	if ((ret = process_binary(handle) < 0)) {
		fprintf(stderr, "process_binary() failed on [%s]\n", handle->path);
		exit(-1);
	}
	

	if (!opts.attach) {
                
                if ((pid = fork()) < 0) {
                        perror("fork");
                        exit(-1);
                }
                if (pid == 0) {
                        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
                                perror("PTRACE_TRACEME");
                                exit(-1);
                        }
			ptraceOpts = PTRACE_O_TRACECLONE|PTRACE_O_TRACEFORK|PTRACE_O_TRACEEXEC|PTRACE_O_TRACEEXIT|PTRACE_O_EXITKILL;
                        ptrace(PTRACE_SETOPTIONS, 0, 0, ptraceOpts); 
			execve(handle->path, handle->args, envp);
                        exit(0);
                }
		wait(&status);
		

		handle->pid = pid;
		if (opts.debug)
			printf("[+] Calling instrument_process()\n");
		instrument_process(handle);
                
		if (opts.debug)
			printf("[+] Calling examine_process()\n");
		examine_process(handle);
                goto done;
        }

	printf("Attaching to %d\n", handle->pid);
	
	if (ptrace(PTRACE_ATTACH, handle->pid, NULL, NULL) == -1) {
                perror("PTRACE_ATTACH");
                exit(-1);
        }

	wait(&status);
      //  waitpid(handle->pid, &status, WUNTRACED);
        instrument_process(handle);
	examine_process(handle);

	for (i = 0; i < ac; i++) 
		printf("arg[%d]: %s\n", i, handle->args[i]);

	
	
done:
	free(handle);
	exit(0);
}

