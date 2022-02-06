# See COPYRIGHT for copyright information.

#include <inc/mmu.h>
#include <inc/memlayout.h>
#include <inc/trap.h>
#include <kern/picirq.h>
# exceptions/interrupts

# TRAPHANDLER defines a globally-visible function for handling a trap.
# It pushes a trap number onto the stack, then jumps to _alltraps.
# Use TRAPHANDLER for traps where the CPU automatically pushes an error code.

# You shouldn't call a TRAPHANDLER function from C, but you may
# need to _declare_ one in C (for instance, to get a function pointer
# during IDT setup).  You can declare the function with
#   void NAME();
# where NAME is the argument passed to TRAPHANDLER.

#define TRAPHANDLER(name, num) \
	.globl name;               \
	.type name, @function;     \
	.align 2;                  \
	name:                      \
	pushl $(num);              \
	jmp _alltraps              \

# Use TRAPHANDLER_NOEC for traps where the CPU doesn't push an error code.
# It pushes a 0 in place of the error code, so the trap frame has the same
# format in either case.
 
#define TRAPHANDLER_NOEC(name, num) \
	.globl name;                    \
	.type name, @function;          \
	.align 2;                       \
	name:                           \
	pushl $0;                       \
	pushl $(num);                   \
	jmp _alltraps                   \

.text

TRAPHANDLER_NOEC(H_DIVIDE, T_DIVIDE );
TRAPHANDLER_NOEC(H_DEBUG,  T_DEBUG  );
TRAPHANDLER_NOEC(H_NMI,    T_NMI    );
TRAPHANDLER_NOEC(H_BRKPT,  T_BRKPT  );
TRAPHANDLER_NOEC(H_OFLOW,  T_OFLOW  );
TRAPHANDLER_NOEC(H_BOUND,  T_BOUND  );
TRAPHANDLER_NOEC(H_ILLOP,  T_ILLOP  );
TRAPHANDLER_NOEC(H_DEVICE, T_DEVICE );
TRAPHANDLER(H_DBLFLT,      T_DBLFLT );
# TRAPHANDLER(H_COPROC,      T_COPROC );
TRAPHANDLER(H_TSS,         T_TSS    );
TRAPHANDLER(H_SEGNP,       T_SEGNP  );
TRAPHANDLER(H_STACK,       T_STACK  );
TRAPHANDLER(H_GPFLT,       T_GPFLT  );
TRAPHANDLER(H_PGFLT,       T_PGFLT  );
# TRAPHANDLER(H_RES,         T_RES    );
TRAPHANDLER(H_FPERR,       T_FPERR  );
TRAPHANDLER(H_ALIGN,       T_ALIGN  );
TRAPHANDLER(H_MCHK,        T_MCHK   );
TRAPHANDLER(H_SIMDERR,     T_SIMDERR);
TRAPHANDLER_NOEC(H_SYSCALL,T_SYSCALL);
TRAPHANDLER_NOEC(H_DEFAULT,T_DEFAULT);

# IRQ INTERUPTS
TRAPHANDLER_NOEC(H_IRQ_0, IRQ_OFFSET     );
TRAPHANDLER_NOEC(H_IRQ_1, IRQ_OFFSET + 1 );
TRAPHANDLER_NOEC(H_IRQ_2, IRQ_OFFSET + 2 );
TRAPHANDLER_NOEC(H_IRQ_3, IRQ_OFFSET + 3 );
TRAPHANDLER_NOEC(H_IRQ_4, IRQ_OFFSET + 4 );
TRAPHANDLER_NOEC(H_IRQ_5, IRQ_OFFSET + 5 );
TRAPHANDLER_NOEC(H_IRQ_6, IRQ_OFFSET + 6 );
TRAPHANDLER_NOEC(H_IRQ_7, IRQ_OFFSET + 7 );
TRAPHANDLER_NOEC(H_IRQ_8, IRQ_OFFSET + 8 );
TRAPHANDLER_NOEC(H_IRQ_9, IRQ_OFFSET + 9 );
TRAPHANDLER_NOEC(H_IRQ_10,IRQ_OFFSET + 10);
TRAPHANDLER_NOEC(H_IRQ_11,IRQ_OFFSET + 11);
TRAPHANDLER_NOEC(H_IRQ_12,IRQ_OFFSET + 12);
TRAPHANDLER_NOEC(H_IRQ_13,IRQ_OFFSET + 13);
TRAPHANDLER_NOEC(H_IRQ_14,IRQ_OFFSET + 14);
TRAPHANDLER_NOEC(H_IRQ_15,IRQ_OFFSET + 15);

_alltraps:
	pushl %ds
	pushl %es 
	pushal
	movw $GD_KD, %ax
	movw %ax, %ds 
	movw %ax, %es 
	pushl %esp 
	call trap
