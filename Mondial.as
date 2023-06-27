.global _start
.extern s, len, overtime

.section .text 
_start:
	movq $1, %rax 
	movq $1, %rdi
	movq $s, %rsi 
	movq $len, %rdx 
	syscall
	movl $end, overtime(%rip)
	jmpq *overtime 
	movq $60, %rax 
	syscall
end:
	imulq %rax, %rdx
	movq %rdx, %rdi 
	movq $60, %rax 
	syscall
