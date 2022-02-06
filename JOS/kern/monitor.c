// Simple command-line kernel monitor useful for
// controlling the kernel and exploring the system interactively.

#include <inc/stdio.h>
#include <inc/string.h>
#include <inc/memlayout.h>
#include <inc/assert.h>
#include <inc/x86.h>

#include <kern/console.h>
#include <kern/monitor.h>
#include <kern/kdebug.h>
#include <kern/trap.h>
#include <kern/pmap.h>

#define CMDBUF_SIZE	80	// enough for one VGA text line


struct Command {
	const char *name;
	const char *desc;
	// return -1 to force monitor to exit
	int (*func)(int argc, char** argv, struct Trapframe* tf);
};

// LAB 1: add your command to here...
static struct Command commands[] = {
	{ "commands", "Display this list of commands.", mon_help },
	{ "kerninfo", "Display information about the kernel.", mon_kerninfo },
	{ "backtrace", "Display backtrace.", mon_backtrace },
	{ "pagedir","Display page directory.", mon_pagemap},
	{ "help","display help.", mon_help},
};

/***** Implementations of basic kernel monitor commands *****/

int
mon_help(int argc, char **argv, struct Trapframe *tf)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(commands); i++)
		cprintf("%s - %s\n", commands[i].name, commands[i].desc);
	cprintf("\n");
	return 0;
}

int
mon_kerninfo(int argc, char **argv, struct Trapframe *tf)
{
	extern char _start[], entry[], etext[], edata[], end[];

	cprintf("Special kernel symbols:\n");
	cprintf("  _start                  %08x (phys)\n", _start);
	cprintf("  entry  %08x (virt)  %08x (phys)\n", entry, entry - KERNBASE);
	cprintf("  etext  %08x (virt)  %08x (phys)\n", etext, etext - KERNBASE);
	cprintf("  edata  %08x (virt)  %08x (phys)\n", edata, edata - KERNBASE);
	cprintf("  end    %08x (virt)  %08x (phys)\n", end, end - KERNBASE);
	cprintf("Kernel executable memory footprint: %dKB\n",
		ROUNDUP(end - entry, 1024) / 1024);
	return 0;
}

int
mon_backtrace(int argc, char **argv, struct Trapframe *tf)
{
	//cprintf("KaOS v0.0.1a\n");
	int* ebp;
	ebp = (int*)read_ebp();
	cprintf("Stack Backtrace:\n");
	do {
		struct Eipdebuginfo info;
		cprintf("  ebp %08x  eip %08x  args %08x %08x %08x %08x %08x\n",
			ebp,					// ebp
			(int*)ebp[1],	// eip
			(int*)ebp[2],	// arg1
			(int*)ebp[3],	// arg2
			(int*)ebp[4],	// arg3
			(int*)ebp[5],	// arg4
			(int*)ebp[6]);  // arg5
		int c;
		int err = debuginfo_eip(ebp[1],&info);
		char buf[info.eip_fn_namelen+1];
		for(c = 0;c < info.eip_fn_namelen;c++) {
			buf[c] = (char)info.eip_fn_name[c];
		}
		buf[c+1] = '\0';
		cprintf("	%s:%d: %s+%d\n",info.eip_file,info.eip_line,buf,ebp[1]-info.eip_fn_addr);
		// goto next ebp
		ebp = (int*)ebp[0];
	} while(ebp != 0);
	return 0;
}
int
mon_pagemap(int argc, char **argv, struct Trapframe *tf) 
{
	page_map();
	return 0;
}



/***** Kernel monitor command interpreter *****/

#define WHITESPACE "\t\r\n "
#define MAXARGS 16

static int
runcmd(char *buf, struct Trapframe *tf)
{
	int argc;
	char *argv[MAXARGS];
	int i;

	// Parse the command buffer into whitespace-separated arguments
	argc = 0;
	argv[argc] = 0;
	while (1) {
		// gobble whitespace
		while (*buf && strchr(WHITESPACE, *buf))
			*buf++ = 0;
		if (*buf == 0)
			break;

		// save and scan past next arg
		if (argc == MAXARGS-1) {
			cprintf("Too many arguments (max %d)\n", MAXARGS);
			return 0;
		}
		argv[argc++] = buf;
		while (*buf && !strchr(WHITESPACE, *buf))
			buf++;
	}
	argv[argc] = 0;

	// Lookup and invoke the command
	if (argc == 0)
		return 0;
	for (i = 0; i < ARRAY_SIZE(commands); i++) {
		if (strcmp(argv[0], commands[i].name) == 0)
			return commands[i].func(argc, argv, tf);
	}
	cprintf("Unknown command '%s'\n", argv[0]);
	return 0;
}

void
term_intro() {
	cprintf("\n");
	cprintf("\033[33mJOS Terminal!\033[0m\n");
	cprintf("\033[33m/------------------------------/ \033[0m\n");
	cprintf("\033[31mPress [CTRL+a], [x] to exit this system.\033[0m\n");
	cprintf("\033[33mtype  [help] for help using this system.\033[0m\n");
	cprintf("\033[33mtype  [commands] for a list of commands.\033[0m\n");
	cprintf("\033[33m/------------------------------/ \033[0m\n");
	//cprintf("\033[33m\\\\ROOT\\\033[0m:");
}

void
monitor(struct Trapframe *tf)
{
	char *buf;
	
	term_intro();
	
	if (tf != NULL)
		print_trapframe(tf);

	while (1) {
		cprintf("\033[33m");
		buf = readline("//Root/ ");
		if (buf != NULL)
			if (runcmd(buf, tf) < 0)
				break;
		cprintf("\033[0m");
	}
}
