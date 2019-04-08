---
tags: ["pwn", "linux", "kernel", "heap"]
author: "bennofs"
---
# Challenge

> Haikus are easy. But sometimes they don't make sense. Microwave noodles!

The task was a kernel pwn challenge. Attached was a qemu image that contained a simply custom kernel module:

```
                      Midnight Sun CTF presents...

 ██░ ██   █████▒ ██████     ██▓ ██▓███   ▄████▄  
▓██░ ██▒▓██   ▒▒██    ▒    ▓██▒▓██░  ██▒▒██▀ ▀█  
▒██▀▀██░▒████ ░░ ▓██▄      ▒██▒▓██░ ██▓▒▒▓█    ▄ 
░▓█ ░██ ░▓█▒  ░  ▒   ██▒   ░██░▒██▄█▓▒ ▒▒▓▓▄ ▄██▒
░▓█▒░██▓░▒█░   ▒██████▒▒   ░██░▒██▒ ░  ░▒ ▓███▀ ░
 ▒ ░░▒░▒ ▒ ░   ▒ ▒▓▒ ▒ ░   ░▓  ▒▓▒░ ░  ░░ ░▒ ▒  ░
 ▒ ░▒░ ░ ░     ░ ░▒  ░ ░    ▒ ░░▒ ░       ░  ▒   
 ░  ░░ ░ ░ ░   ░  ░  ░      ▒ ░░░       ░        
 ░  ░  ░             ░      ░           ░ ░      
                                        ░        
user@hfs:~$ cat /proc/modules
hfsipc 32768 0 - Live 0x0000000000000000 (O)
user@hfs:~$ 
```

# Analysis
The kernel module provided a simple misc device `/dev/hfs` and four ioctl functions on that device:

- ALLOCATE: allocate a new "channel" (just a data buffer that is identified by an ID) of specified size
- DESTROY: free a channel by ID
- WRITE: write to the data buffer of the specified channel
- READ: read the data buffer of the specified channel

The parameters are passed in a struct given as second param to the ioctl. We can make a simple C program to demonstrate the features of the module:

```c
#include <unistd.h>
#include <string.h>
#include <stropts.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/shm.h>

/* constants for the different commands */
#define ALLOCATE 0xABCD0001
#define DESTROY 0xABCD0002
#define READ 0xABCD0003
#define WRITE 0xABCD0004

/* struct for command parameters.
 * some commands do not use all the fields (for example, ALLOCATE only uses id and size)
*/
typedef struct {
  long id;
  long size;
  char* buf;
} req;

/* file descriptor to the opened device (global variable for convenience) */
int hfs = -1;

/* open the device (must be called at start) */
void open_hfs() {
  hfs = open("/dev/hfs", O_RDWR);
  if (hfs < 0) {
    perror("[-] open hfs failed");
    exit(1);
  }
  printf("[+] open fd: %x\n", hfs);
}


/* perform an ioctl with the given parameters to the HFS kernel module */
void make_call(long action, long id, long size, void* buf) {
  req r = {.id = id, .size = size, .buf = buf };
  if (ioctl(hfs, action, &r) != 0) {
    perror("[-] ioctl failed");
    printf("ioctl args: %lx %lx %lx %p\n", action, id, size, buf);
    exit(1);
  }
}

void main() {
  open_hfs();
  
  make_call(ALLOCATE, 0x1337, 13, 0);
  make_call(WRITE, 0x1337, 13, "Hello world!");
  char buf[13];
  make_call(READ, 0x1337, 13, buf);
  puts(buf);
}
```
To test this locally, we compile our code with `musl-gcc` to build a small static binary and then rebuild the initrd to include our binary:

```bash
# extract initrd
$ mkdir fs; pushd fs; cpio --extract --verbose --format=newc < ../rootfs.img; popd

# build code into fs/main
$ musl-gcc -static -Wall -Wextra main.c -o fs/main

# rebuild initrd
$ pushd fs; find . -print0 | cpio --null --create --verbose --format=newc | gzip -9 > ../initramfs.cpio.gz; popd
```

The kernel module keeps an array of channels, which are represented as structs:

```c
struct channel
{
  __int64 id;
  char *data;
  __int64 size;
};
```
These structs and the buffers for data are both allocated from the kernel heap (via `kmem_cache_alloc` and `kalloc` respectively). The vulnerability is easy to find: the WRITE action has an off-by-one, allowing us to write on byte past the end of the allocated buffer:
```c
if (... action is WRITE ...) {
  ...
  if ( arg_size <= channel->size + 1 ) // BUG is here: note the channel->size + 1
  {
    if ( !copy_from_user(channel->data, arg_buf, arg_size) ) {
      v6 = 0LL;
      printk(&unk_478, arg_size);
      goto LABEL_23;
    }
    goto LABEL_13;
  }
}
```

# Exploitation

Exploitation is a two-step process: first, create an arbitrary read/write primitive using the off-by-one write.
Then, become root using this strong primitive.

## Obtain arbitrary read/write

The kernel allocator is very straightforward: it keeps different regions for each size (see also [1]). For each size, it simply allocates in continuous chunks of the specified size. Freed chunks are reused in LIFO-order.

What this means is that if we allocate a channel with data size 0x20 (the size of the channel struct), the layout of the kernel memory will look as follows:

```plain
...
+0x00 channel struct
+0x20 channel data
+0x40 channel struct
+0x60 channel data
...
```

After freeing the second channel, the layout now is:

```plain
...
+0x00 channel struct
+0x20 channel data
+0x40 free list next_ptr: ptr to +0x60
+0x60 free list next_ptr: ptr to old top of free list
...
```

where the top of the freelist now points to `+0x40`, so the new freelist is `+0x40 -> +0x60 -> ...`
So we can now use the out of bounds write to overwrite the least significant byte of the `next_ptr`.
If we override it so that `next_ptr` points to itself and allocate a new channel afterwards, both the channel struct and the data are allocated at the same position.
We now have an arbitrary read/write primitive because we can overwrite the data and size pointers of the channel struct by writing to the channel data. The new layout looks like this:
```plain
+0x40 channel data and channel struct
```
We change the data ptr of the channel struct to the address of some other channel struct which we want to the control, so that the layout is:
```
+0x00 channel struct of "victim" channel and channel data of "controller channel"
+0x20 channel data
+0x40 channel struct of "controller" channel
```

To read/write anywhere we can now use the "controller" channel to change the "data" ptr of our victim channel to point where we want and then use the READ/WRITE commands on our victim channel.
To ensure that the freelist is fixed again, we set the ID of the "controller" channel to zero, which marks the end of the freelist.

## Get root

To become root, we need to change the `real_cred` and `cred` fields of the `task_struct` for our current task.
If we had code execution in the kernel we could do that using `commit_creds(prepare_kernel_cred(0))`, but we only have read/write. But we can do what `commit_creds` does manually:

- find the task_struct of the current task by reading `current_task` (at 0xffffffff81a3a040)
- overwrite `current_task->real_cred` (offset 0x3b8) and `current_task->cred` (offset 0x3c0) with `init_cred` (at 0xffffffff81a3f1c0)
- spawn a shell

All these addresses are static because the challenge didn't have KASLR and can be found by looking at the provided System.map symbol file. The offset for `real_cred`/`cred` can be found by looking at the initial part of the disassembly for `commit_creds`.

To upload the exploit to the remote server, we can use a simple script:
```python
from pwn import *

r = remote("hfsipc-01.play.midnightsunctf.se", 8192);
r.sendlineafter(b"$", b'echo "start" >&2; while read line; do if [ "$line" = "end" ]; then break; fi; echo -n $line; done > tmp')

payload = b64e(read("./fs/exploit"))
r.recvuntil(b"start\r\n");
sleep(0.5)
to_send = payload.encode()
while to_send:
    r.sendline(to_send[:1000])
    to_send = to_send[1000:]
r.send(b"\nend\n")

r.sendlineafter(b"$", b"base64 -d tmp > exploit; chmod +x exploit")
r.sendlineafter(b"$", b"./exploit")
r.interactive()
```

# References
- [1] https://argp.github.io/2012/01/03/linux-kernel-heap-exploitation/ explaining the linux kernel heap (this challenge used the SLUB allocator, the current Linux default)
