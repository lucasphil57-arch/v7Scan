using System.Management;
using Microsoft.Win32;

namespace EchoScan.Core.Collectors;

public static class Hardware {
    static readonly Dictionary<string, string> Fpga = new() { ["10EE"] = "Xilinx FPGA", ["1172"] = "Altera FPGA", ["1B36"] = "virtio (VM)", ["15AD"] = "VMware (VM)", ["80EE"] = "VirtualBox (VM)", ["1234"] = "QEMU (VM)" };
    public static void Run(Report r) {
        var bus = new List<object>();
        try {
            using var k = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Enum\PCI");
            foreach (var id in k?.GetSubKeyNames() ?? Array.Empty<string>()) {
                var i = id.IndexOf("VEN_", StringComparison.OrdinalIgnoreCase);
                var vid = i >= 0 && id.Length >= i + 8 ? id.Substring(i + 4, 4).ToUpperInvariant() : "";
                if (!Fpga.TryGetValue(vid, out var kind)) continue;
                using var d = k.OpenSubKey(id);
                var desc = (d?.GetValue("DeviceDesc")?.ToString() ?? "").Replace("  ", " ");
                bus.Add(new { id, kind, desc });
                var isFpga = vid is "10EE" or "1172";
                r.Findings.Add(new Finding { Collector = "hardware", Category = isFpga ? "dma" : "vm",
                    Severity = isFpga ? Severity.Critical : Severity.Medium,
                    Label = isFpga ? "Carte FPGA sur le bus PCI" : "Peripherique de virtualisation",
                    Detail = kind + " : " + desc, Evidence = id });
            }
        } catch { }
        r.Data["pci"] = bus;
        try {
            using var s = new ManagementObjectSearcher("SELECT HypervisorPresent, Manufacturer, Model FROM Win32_ComputerSystem");
            foreach (ManagementObject o in s.Get()) {
                r.Data["hyperviseur"] = o["HypervisorPresent"]?.ToString();
                r.Data["fabricant"] = o["Manufacturer"]?.ToString();
                r.Data["modele"] = o["Model"]?.ToString();
                if (o["HypervisorPresent"]?.ToString() == "True")
                    r.Findings.Add(new Finding { Collector = "hardware", Category = "vm", Severity = Severity.High,
                        Label = "Hyperviseur actif", Detail = "machine virtualisee ou Hyper-V",
                        Evidence = o["Manufacturer"] + " " + o["Model"] });
            }
        } catch { }
        try { using var s = new ManagementObjectSearcher("SELECT SerialNumber FROM Win32_BIOS"); foreach (ManagementObject o in s.Get()) r.Data["bios_serie"] = o["SerialNumber"]?.ToString(); } catch { }
    }
}