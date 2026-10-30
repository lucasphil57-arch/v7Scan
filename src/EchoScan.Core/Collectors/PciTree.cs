using System.Runtime.InteropServices;
using System.Text;

namespace EchoScan.Core.Collectors;

public static class PciTree {
    static readonly Dictionary<string, string> Fpga = new(StringComparer.OrdinalIgnoreCase) {
        ["10EE"] = "Xilinx FPGA", ["1172"] = "Altera FPGA", ["1B36"] = "virtio"
    };

    [StructLayout(LayoutKind.Sequential)]
    struct SP_DEVINFO_DATA { public uint cbSize; public Guid ClassGuid; public uint DevInst; public IntPtr Reserved; }

    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern IntPtr SetupDiGetClassDevs(IntPtr cls, string enumerator, IntPtr hwnd, uint flags);
    [DllImport("setupapi.dll", SetLastError = true)]
    static extern bool SetupDiEnumDeviceInfo(IntPtr set, uint index, ref SP_DEVINFO_DATA data);
    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool SetupDiGetDeviceRegistryProperty(IntPtr set, ref SP_DEVINFO_DATA data, uint prop, out uint type, byte[] buffer, uint size, out uint required);
    [DllImport("setupapi.dll")]
    static extern bool SetupDiDestroyDeviceInfoList(IntPtr set);
    [DllImport("cfgmgr32.dll")]
    static extern int CM_Get_DevNode_Status(out uint status, out uint problem, uint devInst, uint flags);

    static string Prop(IntPtr set, ref SP_DEVINFO_DATA d, uint prop) {
        var buf = new byte[1024];
        if (!SetupDiGetDeviceRegistryProperty(set, ref d, prop, out _, buf, (uint)buf.Length, out _)) return "";
        return Encoding.Unicode.GetString(buf).Split((char)0)[0];
    }

    public static void Run(Report r) {
        var found = new List<object>();
        var set = SetupDiGetClassDevs(IntPtr.Zero, "PCI", IntPtr.Zero, 0x02 | 0x04);
        if (set == IntPtr.Zero) return;
        try {
            var d = new SP_DEVINFO_DATA { cbSize = (uint)Marshal.SizeOf<SP_DEVINFO_DATA>() };
            for (uint i = 0; SetupDiEnumDeviceInfo(set, i, ref d); i++) {
                var hwid = Prop(set, ref d, 0x01);
                var desc = Prop(set, ref d, 0x00);
                var cls = Prop(set, ref d, 0x0A);
                if (string.IsNullOrWhiteSpace(hwid)) continue;
                var vid = "";
                var vi = hwid.IndexOf("VEN_", StringComparison.OrdinalIgnoreCase);
                if (vi >= 0 && hwid.Length >= vi + 8) vid = hwid.Substring(vi + 4, 4);
                var problem = 0u;
                CM_Get_DevNode_Status(out _, out problem, d.DevInst, 0);
                var noDriver = problem != 0;

                Fpga.TryGetValue(vid, out var kind);
                var isFpga = kind != null && vid != "1B36";
                var low = desc.ToLowerInvariant();
                var fpgaNamed = isFpga && (low.Contains("fpga") || low.Contains("dma") || low.Contains("xilinx") || low.Contains("altera"));

                if (!isFpga && !noDriver) continue;
                found.Add(new { id = hwid, desc, cls, probleme = problem, fpga = isFpga });

                if (isFpga)
                    r.Findings.Add(new Finding { Collector = "pcie", Category = "dma",
                        Severity = fpgaNamed ? Severity.Critical : Severity.High,
                        Label = "Carte FPGA sur bus PCIe" + (fpgaNamed ? "" : " (nom non confirme)"),
                        Detail = kind + " / " + desc + (noDriver ? " / sans pilote" : ""), Evidence = hwid });
                else if (noDriver)
                    r.Findings.Add(new Finding { Collector = "pcie", Category = "device", Severity = Severity.Low,
                        Label = "Peripherique PCIe sans pilote", Detail = cls + " / " + desc, Evidence = hwid });

                if (noDriver && cls.Contains("PROCESSOR", StringComparison.OrdinalIgnoreCase))
                    r.Findings.Add(new Finding { Collector = "pcie", Category = "dma", Severity = Severity.High,
                        Label = "Peripherique classe processeur sans pilote",
                        Detail = "signature typique d une carte DMA", Evidence = hwid });
            }
        } catch { } finally { SetupDiDestroyDeviceInfoList(set); }
        r.Data["pcie"] = found;
    }
}
