# Klee - 32-bit (i386) tracee regression probe
#
# A freestanding i386 program that issues raw int $0x80 syscalls, so it
# needs no 32-bit libc or loader on the host.  Build with:
#     as --32 -o klee32.o tests/klee32.s && ld -m elf_i386 -static -o klee32 klee32.o
#
# Run inside klee as the main command of a rootfs sandbox with
# --unshare-pid --unshare-user --uid 4242 --gid 4242, where /guest-file
# contains "hi" and /usr is read-only.  It prints one line per check:
#
#   T1=hi          open/read of a guest path (i386 numbers, ebx/ecx args)
#   T2=00000001    getpid() as the sandbox's init
#   T3=00001092    stat64() st_uid rewritten to the virtual uid (0x1092)
#   T4=ffffffe2    O_CREAT under a read-only mount fails with -EROFS
#   T5=00000000    socketcall(SYS_BIND) of a unix socket on a guest path
#   T6=/klee32     readlink(/proc/self/exe) is the guest path
#   T7=00001092    getuid32() is the virtual uid
#   exec-ok / sh   execve() of a 64-bit /bin/sh with 4-byte argv pointers
#
# Every number is printed as 8 hex digits; negative returns show as the
# two's complement of the errno.

        .section .rodata
hexdigits: .ascii "0123456789abcdef"
p_t1:   .ascii "T1="
p_t2:   .ascii "T2="
p_t3:   .ascii "T3="
p_t4:   .ascii "T4="
p_t5:   .ascii "T5="
p_t6:   .ascii "T6="
p_t7:   .ascii "T7="
p_t8:   .ascii "T8="
nl:     .ascii "\n"
path_file: .asciz "/guest-file"
path_ro:   .asciz "/usr/klee-32-erofs"
path_exe:  .asciz "/proc/self/exe"
path_sh:   .asciz "/bin/sh"
arg_sh:    .asciz "sh"
arg_c:     .asciz "-c"
arg_cmd:   .asciz "echo exec-ok; cat /proc/$$/comm"

        .data
argv:   .long arg_sh, arg_c, arg_cmd, 0
sockaddr:
        .short 1                        # AF_UNIX
        .ascii "/tmp/klee32.sock\0"
        .space 91                       # struct sockaddr_un is 110 bytes
sc_socket_args: .long 1, 1, 0           # AF_UNIX, SOCK_STREAM, 0
sc_bind_args:   .long 0, sockaddr, 110  # fd filled in at run time

        .bss
buf:     .space 128
hexbuf:  .space 9
statbuf: .space 160

        .macro PFX label
        mov $\label, %ecx
        mov $3, %edx
        call print
        .endm

        .text
        .globl _start

# print: write(1, ecx, edx)
print:
        push %ebx
        mov $4, %eax
        mov $1, %ebx
        int $0x80
        pop %ebx
        ret

# print_hex: print eax as 8 hex digits and a newline
print_hex:
        push %ebx
        mov $hexbuf, %edi
        mov $8, %ecx
1:      rol $4, %eax
        mov %eax, %edx
        and $0xf, %edx
        movb hexdigits(%edx), %bl
        movb %bl, (%edi)
        inc %edi
        loop 1b
        movb $10, (%edi)
        mov $hexbuf, %ecx
        mov $9, %edx
        call print
        pop %ebx
        ret

_start:
        # T1: open("/guest-file") + read + write
        PFX p_t1
        mov $5, %eax                    # open
        mov $path_file, %ebx
        xor %ecx, %ecx                  # O_RDONLY
        xor %edx, %edx
        int $0x80
        test %eax, %eax
        js t1_err
        mov %eax, %ebx                  # fd
        mov $3, %eax                    # read
        mov $buf, %ecx
        mov $127, %edx
        int $0x80
        test %eax, %eax
        js t1_err
        mov %eax, %edx                  # length, newline included
        mov $buf, %ecx
        call print
        jmp t2
t1_err: call print_hex

t2:     # getpid
        PFX p_t2
        mov $20, %eax
        int $0x80
        call print_hex

        # T3: stat64("/guest-file") -> st_uid
        PFX p_t3
        mov $195, %eax                  # stat64
        mov $path_file, %ebx
        mov $statbuf, %ecx
        int $0x80
        test %eax, %eax
        js t3_err
        mov statbuf+24, %eax            # st_uid in struct stat64
        call print_hex
        jmp t4
t3_err: call print_hex

t4:     # open(O_WRONLY|O_CREAT) on a read-only mount
        PFX p_t4
        mov $5, %eax
        mov $path_ro, %ebx
        mov $0x41, %ecx                 # O_WRONLY|O_CREAT
        mov $0644, %edx
        int $0x80
        call print_hex

        # T5: socketcall(SYS_SOCKET) then socketcall(SYS_BIND)
        PFX p_t5
        mov $102, %eax                  # socketcall
        mov $1, %ebx                    # SYS_SOCKET
        mov $sc_socket_args, %ecx
        int $0x80
        test %eax, %eax
        js t5_out
        mov %eax, sc_bind_args
        mov $102, %eax
        mov $2, %ebx                    # SYS_BIND
        mov $sc_bind_args, %ecx
        int $0x80
t5_out: call print_hex

        # T6: readlink("/proc/self/exe")
        PFX p_t6
        mov $85, %eax                   # readlink
        mov $path_exe, %ebx
        mov $buf, %ecx
        mov $127, %edx
        int $0x80
        test %eax, %eax
        js t6_err
        mov %eax, %edx
        mov $buf, %ecx
        call print
        mov $nl, %ecx
        mov $1, %edx
        call print
        jmp t7
t6_err: call print_hex

t7:     # getuid32
        PFX p_t7
        mov $199, %eax
        int $0x80
        call print_hex

        # T8: execve("/bin/sh", argv, NULL) - a 64-bit program
        mov $11, %eax                   # execve
        mov $path_sh, %ebx
        mov $argv, %ecx
        xor %edx, %edx
        int $0x80
        PFX p_t8                        # only reached if exec failed
        call print_hex
        mov $1, %eax                    # exit(1)
        mov $1, %ebx
        int $0x80
