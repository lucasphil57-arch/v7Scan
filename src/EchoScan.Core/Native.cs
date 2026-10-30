using System.Runtime.InteropServices;

namespace EchoScan.Core;

public static class Native {
    [StructLayout(LayoutKind.Sequential)]
    public struct ModuleInfo {
        public IntPtr Section;
        public IntPtr MappedBase;
        public IntPtr ImageBase;
        public uint ImageSize;
        public uint Flags;
        public ushort LoadOrderIndex;
        public ushort InitOrderIndex;
        public ushort LoadCount;
        public ushort OffsetToFileName;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 256)]
        public byte[] FullPathName;
    }
    [DllImport("ntdll.dll")]
    static extern int NtQuerySystemInformation(int cls, IntPtr buf, int len, out int ret);
    public static List<(string Path, ulong Base, uint Size)> KernelModules() {
        var res = new List<(string, ulong, uint)>();
        var size = 4 * 1024 * 1024;
        var buf = Marshal.AllocHGlobal(size);
        try {
            if (NtQuerySystemInformation(11, buf, size, out _) != 0) return res;
            var count = (uint)Marshal.ReadInt32(buf);
            var stride = Marshal.SizeOf<ModuleInfo>();
            var baseAddr = IntPtr.Add(buf, 8);
            for (var i = 0; i < count; i++) {
                var item = Marshal.PtrToStructure<ModuleInfo>(IntPtr.Add(baseAddr, i * stride));
                var path = System.Text.Encoding.ASCII.GetString(item.FullPathName).Split((char)0)[0];
                if (!string.IsNullOrWhiteSpace(path)) res.Add((path, (ulong)item.ImageBase.ToInt64(), item.ImageSize));
            }
        } catch { } finally { Marshal.FreeHGlobal(buf); }
        return res;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct FileInfo { public uint cbStruct; public IntPtr filePath; public IntPtr hFile; public IntPtr knownSubject; }
    [StructLayout(LayoutKind.Sequential)]
    struct TrustData { public uint cbStruct; public IntPtr policy; public IntPtr sip; public uint uiChoice; public uint revocation; public uint unionChoice; public IntPtr file; public uint stateAction; public IntPtr stateData; public IntPtr urlRef; public uint provFlags; public uint uiContext; }
    [DllImport("wintrust.dll", CharSet = CharSet.Unicode)]
    static extern int WinVerifyTrust(IntPtr hwnd, ref Guid action, ref TrustData data);
    static readonly Guid Action = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
    public static bool IsSigned(string path) {
        if (!File.Exists(path)) return false;
        var fi = new FileInfo { cbStruct = (uint)Marshal.SizeOf<FileInfo>(), filePath = Marshal.StringToHGlobalUni(path) };
        var td = new TrustData { cbStruct = (uint)Marshal.SizeOf<TrustData>(), uiChoice = 2, unionChoice = 1, file = Marshal.AllocHGlobal(Marshal.SizeOf<FileInfo>()), stateAction = 0, provFlags = 0x10 };
        try { Marshal.StructureToPtr(fi, td.file, false); var act = Action; return WinVerifyTrust(IntPtr.Zero, ref act, ref td) == 0; }
        catch { return false; }
        finally { Marshal.FreeHGlobal(fi.filePath); Marshal.FreeHGlobal(td.file); }
    }
}

