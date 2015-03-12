#include "binflow.h"

struct options opts;

/*
 * These functions are specifically designed for Linux's /proc/pid/maps
 * and not FreeBSD's /proc/pid/map file. A FreeBSD version should be written
 * for use on FreeBSD OS.
 */
char * get_path(int pid)
{
        char tmp[64], buf[256];
        char path[256], *ret, *p;
        FILE *fd;
        int i;
 
	if (opts.debug)
		printf("[DEBUG] get_path()\n");
	
	if (pid == 0)
       		strcpy(tmp, "/proc/self/maps");
	else
        	snprintf(tmp, 64, "/proc/%d/maps", pid);
        
        if ((fd = fopen(tmp, "r")) == NULL) {
                fprintf(stderr, "Unable to open %s: %s\n", tmp, strerror(errno));
                exit(-1);
        }
        
        if (fgets(buf, sizeof(buf), fd) == NULL)
                return NULL;
        p = strchr(buf, '/');
        if (!p)
                return NULL;
        for (i = 0; *p != '\n' && *p != '\0'; p++, i++)
                path[i] = *p;
        path[i] = '\0';
        ret = (char *)heapAlloc(i + 1);
        strcpy(ret, path);
        if (strstr(ret, ".so")) {
                fprintf(stderr, "Process ID: %d appears to be a shared library; file must be an executable. (path: %s)\n",pid, ret);
                exit(-1);
        }
        return ret;
}

void get_address_space(struct address_space *addrspace, int pid, char *path)
{
        char tmp[64], buf[256];
        char *p, addrstr[32];
        FILE *fd;
        int i, lc;
 
	if (opts.debug)
		printf("[DEBUG] get_address_space()\n");

	if (pid == 0)
		strcpy(tmp, "/proc/self/maps");
	else
        	snprintf(tmp, 64, "/proc/%d/maps", pid);

        if ((fd = fopen(tmp, "r")) == NULL) {
                fprintf(stderr, "Unable to open %s: %s\n", tmp, strerror(errno));
                exit(-1);
        }
        
        for (lc = 0, p = buf; fgets(buf, sizeof(buf), fd) != NULL; lc++) {
                /*
                 * Get executable text and data
                 * segment addresses.
                 */
                if ((char *)strchr(buf, '/') && lc == 0) {
                        for (i = 0; *p != '-'; i++, p++) 
                                addrstr[i] = *p;
                        addrstr[i] = '\0';
                        addrspace[TEXT_SPACE].svaddr = strtoul(addrstr, NULL, 16);
                        for (p = p + 1, i = 0; *p != 0x20; i++, p++)
                                addrstr[i] = *p;
                        addrstr[i] = '\0';
                        addrspace[TEXT_SPACE].evaddr = strtoul(addrstr, NULL, 16);
                        addrspace[TEXT_SPACE].size = addrspace[TEXT_SPACE].evaddr - addrspace[TEXT_SPACE].svaddr;
                }
                
                if ((char *)strchr(buf, '/') && strstr(buf, path) && strstr(buf, "rw-p")) {
                        for (i = 0, p = buf; *p != '-'; i++, p++)
                                addrstr[i] = *p;                                
                        addrstr[i] = '\0';
                        addrspace[DATA_SPACE].svaddr = strtoul(addrstr, NULL, 16);
                        for (p = p + 1, i = 0; *p != 0x20; i++, p++)
                                addrstr[i] = *p;
                        addrstr[i] = '\0';
                        addrspace[DATA_SPACE].evaddr = strtoul(addrstr, NULL, 16);
                        addrspace[DATA_SPACE].size = addrspace[DATA_SPACE].evaddr - addrspace[DATA_SPACE].svaddr;
                }
                /*
                 * Get the heap segment address layout
    		 */
                if (strstr(buf, "[heap]")) {
                        for (i = 0, p = buf; *p != '-'; i++, p++)
                                addrstr[i] = *p;
                        addrstr[i] = '\0';
                        addrspace[HEAP_SPACE].svaddr = strtoul(addrstr, NULL, 16);
                        for (p = p + 1, i = 0; *p != 0x20; i++, p++)
                                addrstr[i] = *p;
                        addrstr[i] = '\0';
                        addrspace[HEAP_SPACE].evaddr = strtoul(addrstr, NULL, 16);
                        addrspace[HEAP_SPACE].size = addrspace[HEAP_SPACE].evaddr - addrspace[DATA_SPACE].svaddr;
                }
                /*
                 * Get the stack segment layout
                 */
                if (strstr(buf, "[stack]")) {
                         for (i = 0, p = buf; *p != '-'; i++, p++)
                                addrstr[i] = *p;
                        addrstr[i] = '\0';
                        addrspace[STACK_SPACE].svaddr = strtoul(addrstr, NULL, 16);
                        for (p = p + 1, i = 0; *p != 0x20; i++, p++)
                                addrstr[i] = *p;
                        addrstr[i] = '\0';
                        addrspace[STACK_SPACE].evaddr = strtoul(addrstr, NULL, 16);
                        addrspace[STACK_SPACE].size = addrspace[STACK_SPACE].evaddr - addrspace[STACK_SPACE].svaddr;
                }
         }
}


