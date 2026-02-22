# Level 2

*Step-by-step solution for Rainfall Level 2 with detailed return address validation bypass and heap-based shellcode injection analysis*

## Initial Analysis

### 1. Examine the Binary
```bash
level2@RainFall:~$ ls -la
total 17
dr-xr-x---+ 1 level2 level2   80 Mar  6  2016 .
dr-x--x--x  1 root   root    340 Sep 23  2015 ..
-rw-r--r--  1 level2 level2  220 Apr  3  2012 .bash_logout
-rw-r--r--  1 level2 level2 3530 Sep 23  2015 .bashrc
-rwsr-s---+ 1 level3 users  5403 Mar  6  2016 level2
-rw-r--r--+ 1 level2 level2   65 Sep 23  2015 .pass
-rw-r--r--  1 level2 level2  675 Apr  3  2012 .profile

level2@RainFall:~$ file level2
level2: setuid setgid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0x46834d5b88d04847b6615b8c8e1a0a64c9e4318a, not stripped
```

**Key observations:**
- **setuid and setgid binary** (s flags in permissions)
- Owned by **level3** user
- When executed, runs with **level3 privileges**

### 2. Test Basic Execution Behavior
```bash
level2@RainFall:~$ ./level2
hello
hello

level2@RainFall:~$ echo "test input" | ./level2
test input

level2@RainFall:~$ python -c 'print "A"*100' | ./level2
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Segmentation fault
```

**Initial Pattern Discovery:**
- **Interactive program**: Reads input and echoes it back
- **Normal behavior**: Short input works fine, echoes and exits
- **Long input causes segfault**: Buffer overflow vulnerability confirmed
- **No visible validation**: Program accepts any input length initially

**Critical Discovery**: The segfault with long input confirms a buffer overflow, but the echo behavior suggests the program continues after input, unlike a simple buffer overflow crash.

## Reverse Engineering - Understanding the Control Flow

### 3. Function Analysis - Discovering the Program Structure
```bash
level2@RainFall:~$ gdb level2
(gdb) info functions
All defined functions:
Non-debugging symbols:
0x080483a0  printf@plt
0x080483b0  fflush@plt      ← Output buffer flush
0x080483c0  gets@plt        ← Dangerous input function!
0x080483d0  _exit@plt       ← Program termination
0x080483e0  strdup@plt      ← String duplication + heap allocation
0x080483f0  puts@plt        ← String output
0x080484d4  p               ← Main logic function
0x0804853f  main            ← Entry point
```

**Function Analysis:**
- **gets@plt**: The dangerous unbounded input function
- **strdup@plt**: Allocates memory on heap and copies string
- **printf@plt and _exit@plt**: Suggests error handling
- **Single custom function p()**: Contains main program logic

### 4. Main Function Analysis
```bash
(gdb) disas main
Dump of assembler code for function main:
   0x0804853f <+0>:     push   %ebp
   0x08048540 <+1>:     mov    %esp,%ebp
   0x08048542 <+3>:     and    $0xfffffff0,%esp
   0x08048545 <+6>:     call   0x80484d4 <p>     # Call function p()
   0x0804854a <+11>:    leave
   0x0804854b <+12>:    ret
```

**Main Function Discovery:**
- **Simple wrapper**: Just calls function p() and returns
- **All logic in p()**: The vulnerability and exploitation target is in p()

### 5. Function p() Deep Analysis - The Security Check Discovery
```bash
(gdb) disas p
Dump of assembler code for function p:
   0x080484d4 <+0>:     push   %ebp
   0x080484d5 <+1>:     mov    %esp,%ebp
   0x080484d7 <+3>:     sub    $0x68,%esp        # 104 bytes local space
   
   # Flush output buffer
   0x080484da <+6>:     mov    0x8049860,%eax    # stdout
   0x080484df <+11>:    mov    %eax,(%esp)
   0x080484e2 <+14>:    call   0x80483b0 <fflush@plt>
   
   # Read user input - VULNERABLE!
   0x080484e7 <+19>:    lea    -0x4c(%ebp),%eax  # Buffer at EBP-76
   0x080484ea <+22>:    mov    %eax,(%esp)
   0x080484ed <+25>:    call   0x80483c0 <gets@plt>  # gets(buffer)
   
   # SECURITY CHECK - Return address validation!
   0x080484f2 <+30>:    mov    0x4(%ebp),%eax    # Load return address
   0x080484f5 <+33>:    mov    %eax,-0xc(%ebp)   # Store locally
   0x080484f8 <+36>:    mov    -0xc(%ebp),%eax   # Load stored address
   0x080484fb <+39>:    and    $0xb0000000,%eax  # Mask with 0xb0000000
   0x08048500 <+44>:    cmp    $0xb0000000,%eax  # Compare
   0x08048505 <+49>:    jne    0x8048527 <p+83>  # Jump if valid
```

**Critical Security Check Discovery:**
The program implements a **return address validation** mechanism!
- **Loads return address** from stack (EBP+4)
- **Masks with 0xb0000000** to check address range  
- **Compares with 0xb0000000** to detect stack addresses
- **Blocks stack-based exploitation** - traditional buffer overflow won't work!

### 6. Security Violation and Normal Paths
```bash
   # Security violation path (if return address looks like stack)
   0x08048507 <+51>:    mov    $0x8048620,%eax   # Error message
   0x0804850c <+56>:    mov    -0xc(%ebp),%edx   # Corrupted address
   0x0804850f <+59>:    mov    %edx,0x4(%esp)    # Push address
   0x08048513 <+63>:    mov    %eax,(%esp)       # Push format
   0x08048516 <+66>:    call   0x80483a0 <printf@plt>  # Print error
   0x0804851b <+71>:    movl   $0x1,(%esp)       # Exit code 1
   0x08048522 <+78>:    call   0x80483d0 <_exit@plt>   # Terminate
   
   # Normal execution path (if return address is valid)
   0x08048527 <+83>:    lea    -0x4c(%ebp),%eax  # Buffer address
   0x0804852a <+86>:    mov    %eax,(%esp)       
   0x0804852d <+89>:    call   0x80483f0 <puts@plt>   # Echo input
   0x08048532 <+94>:    lea    -0x4c(%ebp),%eax  # Buffer address again
   0x08048535 <+97>:    mov    %eax,(%esp)       
   0x08048538 <+100>:   call   0x80483e0 <strdup@plt> # Copy to heap!
   0x0804853d <+105>:   leave
   0x0804853e <+106>:   ret                      # Return with overflow
```

**Control Flow Analysis:**
- **Security violation**: If return address starts with 0xb, print error and exit
- **Normal execution**: Echo input with puts(), then call strdup()
- **strdup() call**: Creates heap copy of our input - **KEY EXPLOITATION VECTOR!**