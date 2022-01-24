	.file	"ios_encrypt_password.c"
	.text
	.section	.rodata
	.align 8
.LC0:
	.string	"ios_encrypt_password: entered: type=%d\n"
	.align 8
.LC1:
	.string	"Error: salts for type 6 passwords must be exactly %d characters long\n"
	.align 8
.LC2:
	.string	"Error: illegal salt for type 6 password"
	.align 8
.LC3:
	.string	"ios_encrypt_password: converting master key"
.LC4:
	.string	"unarmored length = %d\n"
.LC5:
	.string	"Getting output buffer"
.LC6:
	.string	"All done : result = %lx\n"
	.text
	.globl	ios_encrypt_password
	.type	ios_encrypt_password, @function
ios_encrypt_password:
.LFB6:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$528, %rsp
	movl	%edi, -484(%rbp)
	movq	%rsi, -496(%rbp)
	movq	%rdx, -504(%rbp)
	movq	%rcx, -512(%rbp)
	movq	%r8, -520(%rbp)
	movl	%r9d, -488(%rbp)
	movl	-484(%rbp), %eax
	movl	%eax, %esi
	movl	$.LC0, %edi
	movl	$0, %eax
	call	printf
	movq	-504(%rbp), %rax
	movq	%rax, %rdi
	call	strlen
	movl	%eax, -20(%rbp)
	movl	$0, -16(%rbp)
	cmpl	$6, -484(%rbp)
	je	.L2
	movl	$0, %eax
	jmp	.L18
.L2:
	cmpq	$0, -512(%rbp)
	je	.L4
	movq	-512(%rbp), %rax
	movq	%rax, %rdi
	call	strlen
	cmpq	$12, %rax
	je	.L5
	movl	$12, %esi
	movl	$.LC1, %edi
	movl	$0, %eax
	call	printf
	movl	$0, %eax
	jmp	.L18
.L5:
	movq	-512(%rbp), %rax
	movq	%rax, %rdi
	call	strlen
	movl	%eax, %esi
	leaq	-280(%rbp), %rdx
	movq	-512(%rbp), %rax
	movl	$8, %ecx
	movq	%rax, %rdi
	call	decode_printable_hash_type_6
	testl	%eax, %eax
	jne	.L6
	movl	$.LC2, %edi
	call	puts
	movl	$0, %eax
	jmp	.L18
.L4:
	leaq	-280(%rbp), %rax
	movl	$8, %esi
	movq	%rax, %rdi
	call	get_random_bytes
.L6:
	movl	$.LC3, %edi
	call	puts
	leaq	-480(%rbp), %rax
	movq	%rax, %rdi
	call	MD5Init
	movq	-496(%rbp), %rax
	movq	%rax, %rdi
	call	strlen
	movl	%eax, %edx
	movq	-496(%rbp), %rcx
	leaq	-480(%rbp), %rax
	movq	%rcx, %rsi
	movq	%rax, %rdi
	call	MD5Update
	leaq	-480(%rbp), %rdx
	leaq	-320(%rbp), %rax
	movq	%rdx, %rsi
	movq	%rax, %rdi
	call	MD5Final
	leaq	-240(%rbp), %rdx
	leaq	-320(%rbp), %rax
	movl	$128, %esi
	movq	%rax, %rdi
	call	AES_set_encrypt_key
	testl	%eax, %eax
	je	.L7
	movl	$0, %eax
	jmp	.L18
.L7:
	leaq	-304(%rbp), %rax
	movl	$16, %edx
	movl	$0, %esi
	movq	%rax, %rdi
	call	memset
	movq	-280(%rbp), %rax
	movq	%rax, -304(%rbp)
	leaq	-240(%rbp), %rdx
	leaq	-256(%rbp), %rsi
	leaq	-304(%rbp), %rax
	movl	$1, %ecx
	movq	%rax, %rdi
	call	AES_ecb_encrypt
	movb	$1, -289(%rbp)
	leaq	-240(%rbp), %rdx
	leaq	-272(%rbp), %rsi
	leaq	-304(%rbp), %rax
	movl	$1, %ecx
	movq	%rax, %rdi
	call	AES_ecb_encrypt
	leaq	-240(%rbp), %rdx
	leaq	-272(%rbp), %rax
	movl	$128, %esi
	movq	%rax, %rdi
	call	AES_set_encrypt_key
	testl	%eax, %eax
	je	.L8
	movl	$0, %eax
	jmp	.L18
.L8:
	movl	-20(%rbp), %eax
	addl	$13, %eax
	movl	%eax, %eax
	movq	%rax, -32(%rbp)
	movq	-32(%rbp), %rax
	movq	%rax, %rdi
	call	malloc
	movq	%rax, -8(%rbp)
	movq	-8(%rbp), %rax
	movq	%rax, -40(%rbp)
	cmpq	$0, -40(%rbp)
	jne	.L9
	movl	$0, %eax
	jmp	.L18
.L9:
	movq	-280(%rbp), %rdx
	movq	-8(%rbp), %rax
	movq	%rdx, (%rax)
	addq	$8, -8(%rbp)
	movl	$0, -12(%rbp)
	jmp	.L10
.L12:
	movl	-12(%rbp), %eax
	andl	$15, %eax
	testl	%eax, %eax
	jne	.L11
	leaq	-304(%rbp), %rax
	movl	$16, %edx
	movl	$0, %esi
	movq	%rax, %rdi
	call	memset
	movl	-12(%rbp), %eax
	shrl	$4, %eax
	movb	%al, -301(%rbp)
	leaq	-240(%rbp), %rdx
	leaq	-304(%rbp), %rsi
	leaq	-304(%rbp), %rax
	movl	$1, %ecx
	movq	%rax, %rdi
	call	AES_ecb_encrypt
.L11:
	movl	-12(%rbp), %edx
	movq	-504(%rbp), %rax
	addq	%rdx, %rax
	movzbl	(%rax), %edx
	movl	-12(%rbp), %eax
	andl	$15, %eax
	movl	%eax, %eax
	movzbl	-304(%rbp,%rax), %eax
	xorl	%edx, %eax
	movb	%al, -41(%rbp)
	movq	-8(%rbp), %rax
	leaq	1(%rax), %rdx
	movq	%rdx, -8(%rbp)
	movzbl	-41(%rbp), %edx
	movb	%dl, (%rax)
	addl	$1, -12(%rbp)
.L10:
	movl	-12(%rbp), %eax
	cmpl	-20(%rbp), %eax
	jbe	.L12
	movl	-20(%rbp), %eax
	leal	1(%rax), %ecx
	movl	-20(%rbp), %eax
	notq	%rax
	movq	%rax, %rdx
	movq	-8(%rbp), %rax
	addq	%rax, %rdx
	leaq	-352(%rbp), %rsi
	leaq	-256(%rbp), %rax
	movq	%rsi, %r8
	movl	$16, %esi
	movq	%rax, %rdi
	call	hmac_sha1
	movl	-352(%rbp), %edx
	movq	-8(%rbp), %rax
	movl	%edx, (%rax)
	addq	$4, -8(%rbp)
	movq	-32(%rbp), %rax
	movl	%eax, -48(%rbp)
	movl	-48(%rbp), %eax
	movl	%eax, %esi
	movl	$.LC4, %edi
	movl	$0, %eax
	call	printf
	movl	-48(%rbp), %eax
	movl	%eax, %edi
	call	get_printable_hash_output_type_6_len
	movl	%eax, -52(%rbp)
	movl	$.LC5, %edi
	call	puts
	cmpq	$0, -520(%rbp)
	jne	.L13
	movl	-52(%rbp), %eax
	movl	%eax, -488(%rbp)
	movl	-488(%rbp), %eax
	movq	%rax, %rdi
	call	malloc
	movq	%rax, -520(%rbp)
	cmpq	$0, -520(%rbp)
	jne	.L14
	movq	-40(%rbp), %rax
	movq	%rax, %rdi
	call	free
	movl	$0, %eax
	jmp	.L18
.L14:
	movl	$1, -16(%rbp)
	jmp	.L15
.L13:
	movl	-488(%rbp), %eax
	cmpl	-52(%rbp), %eax
	jnb	.L15
	movq	-40(%rbp), %rax
	movq	%rax, %rdi
	call	free
	movl	$0, %eax
	jmp	.L18
.L15:
	movl	-488(%rbp), %ecx
	movq	-520(%rbp), %rdx
	movl	-48(%rbp), %esi
	movq	-40(%rbp), %rax
	movq	%rax, %rdi
	call	get_printable_hash_type_6
	testl	%eax, %eax
	jne	.L16
	movq	-40(%rbp), %rax
	movq	%rax, %rdi
	call	free
	cmpl	$0, -16(%rbp)
	je	.L17
	movq	-520(%rbp), %rax
	movq	%rax, %rdi
	call	free
.L17:
	movl	$0, %eax
	jmp	.L18
.L16:
	movq	-40(%rbp), %rax
	movq	%rax, %rdi
	call	free
	movq	-520(%rbp), %rax
	movq	%rax, %rsi
	movl	$.LC6, %edi
	movl	$0, %eax
	call	printf
	movq	-520(%rbp), %rax
.L18:
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE6:
	.size	ios_encrypt_password, .-ios_encrypt_password
	.ident	"GCC: (GNU) 8.3.1 20190507 (Red Hat 8.3.1-4)"
	.section	.note.GNU-stack,"",@progbits
