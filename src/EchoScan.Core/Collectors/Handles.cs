using System.Diagnostics;
using System.Runtime.InteropServices;

namespace EchoScan.Core.Collectors;

public static class Handles {
    [StructLayout(LayoutKind.Sequential)]
    struct Entry { public ushort Pid; public ushort Cbt; public byte Type; public byte Attr; public ushort Handle; public IntPtr Object; public uint Access; }

    [DllImport("ntdll.dll")]
    static extern int NtQuerySystemInformation(int cls, IntPtr buf, int len, out int ret);

    public static void Run(Report r) {
        var size = 16 * 1024 * 1024;
        var buf = Marshal.AllocHGlobal(size);
        var counts = new Dictionary<ushort, int>();
        try {
            if (NtQuerySystemInformation(16, buf, size, out _) != 0) return;
            var count = (uint)Marshal.ReadInt32(buf);
            var stride = Marshal.SizeOf<Entry>();
            var baseAddr = IntPtr.Add(buf, 8);
            if ((long)count * stride > size) count = (uint)(size / stride);
            for (var i = 0; i < count; i++) {
                var e = Marshal.PtrToStructure<Entry>(IntPtr.Add(baseAddr, (int)(i * stride)));
                counts[e.Pid] = counts.GetValueOrDefault(e.Pid) + 1;
            }
        } catch { } finally { Marshal.FreeHGlobal(buf); }

        var procs = new Dictionary<ushort, string>();
        foreach (var p in Process.GetProcesses())
            try { procs[(ushort)p.Id] = p.ProcessName; } catch { }

        var heavy = counts.Where(kv => procs.ContainsKey(kv.Key) && kv.Value > 250)
            .OrderByDescending(kv => kv.Value).Take(25)
            .Select(kv => new { processus = procs[kv.Key], pid = kv.Key, handles = kv.Value }).ToList();
        r.Data["handles_lourds"] = heavy;

        foreach (var h in heavy)
            if (SignatureDb.Match(h.processus) is { } s)
                r.Findings.Add(new Finding { Collector = "handles", Category = s.Category,
                    Severity = (Severity)s.Severity,
                    Label = s.Label + " tient des handles",
                    Detail = h.handles + " handles ouverts", Evidence = h.processus });

        foreach (var name in new[] { "FiveM", "FiveM_GTAProcess" })
            foreach (var p in Process.GetProcessesByName(name))
                try { r.Data["handles_" + name] = p.HandleCount; } catch { }
    }
}
