## Shellcode Injection
- A simple shellcode injection poc built in c#. The shellcode is written in the text files as a long string. This is because the program loads the shellcode from the resources section.

### Usage:
- Takes a process ID as the only argument.
```bash
.\shellcodeinjection.exe 1337
```

- Currently has the calculator poping shellcode from msfvenom.

### TODO:
- Fix the x86 shellcode. Currently only x64 processes are injected.
