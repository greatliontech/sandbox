#include "textflag.h"

// func int80getpid() int32 — __NR_getpid on the i386 ABI is 20.
TEXT ·int80getpid(SB),NOSPLIT,$0-4
	MOVL	$20, AX
	INT	$0x80
	MOVL	AX, ret+0(FP)
	RET
