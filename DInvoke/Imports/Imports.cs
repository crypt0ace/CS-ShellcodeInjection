using System;
using System.Runtime.InteropServices;
using DInvoke.Data;
using static DInvoke.Data.Native;

namespace ShellcodeInjection.Imports
{
    class Imports
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr VirtualAllocExD(IntPtr hProcess, IntPtr lpAddress, int dwSize, UInt32 flAllocationType, UInt32 flProtect);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr CreateRemoteThreadD(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool WriteProcessMemoryD(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, ref int lpNumberOfBytesWritten);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr OpenProcessD(UInt32 dwDesiredAccess, bool bInheritHandle, UInt32 dwProcessId);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool VirtualProtectExD(IntPtr hProcess, IntPtr lpAddress, int dwSize, UInt32 flNewProtect, UInt32 lpflOldProtect);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate Native.NTSTATUS NtOpenProcess(ref IntPtr processHandle, ProcessAccess desiredAccess, ref Native.OBJECT_ATTRIBUTES objectAttributes, ref Native.CLIENT_ID clientId);
        
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate Native.NTSTATUS NtAllocateVirtualMemory(IntPtr processHandle, ref IntPtr baseAddress, IntPtr zeroBits, ref IntPtr regionSize, State allocationType, Protection memoryProtection);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate Native.NTSTATUS NtWriteVirtualMemory(IntPtr processHandle,IntPtr baseAddress, IntPtr buffer, uint bufferLength, ref uint bytesWritten);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate NTSTATUS NtCreateThreadEx(out IntPtr threadHandle, Win32.WinNT.ACCESS_MASK desiredAccess, IntPtr objectAttributes, IntPtr processHandle, IntPtr startAddress, IntPtr parameter, bool createSuspended, int stackZeroBits, int sizeOfStack, int maximumStackSize, IntPtr attributeList);

        public enum State
        {
            MEM_COMMIT = 0x00001000,
            MEM_RESERVE = 0x00002000
        }

        public enum Protection
        {
            PAGE_EXECUTE_READWRITE = 0x40,
            PAGE_EXECUTE = 0x10,
            PAGE_EXECUTE_READ = 0x20,
            PAGE_READWRITE = 0x04
        }
        public enum ProcessAccess
        {
            PROCESS_ALL_ACCESS = 0x000F0000 | 0x00100000 | 0xFFFF,
            PROCESS_CREATE_THREAD = 0x0002,
            PROCESS_QUERY_INFORMATION = 0x0400,
            PROCESS_VM_OPERATION = 0x0008,
            PROCESS_VM_READ = 0x0010,
            PROCESS_VM_WRITE = 0x0020
        }
    }
}
