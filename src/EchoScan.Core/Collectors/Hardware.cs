using System.Management;

namespace EchoScan.Core.Collectors;

public static class Hardware {
    public static void Run(Report r) {
        try {
            using var s = new ManagementObjectSearcher("SELECT HypervisorPresent, Manufacturer, Model FROM Win32_ComputerSystem");
            foreach (ManagementObject o in s.Get()) {
                r.Data["hyperviseur"] = o["HypervisorPresent"]?.ToString();
                r.Data["fabricant"] = o["Manufacturer"]?.ToString();
                r.Data["modele"] = o["Model"]?.ToString();
                if (o["HypervisorPresent"]?.ToString() == "True")
                    r.Findings.Add(new Finding { Collector = "hardware", Category = "vm", Severity = Severity.Medium,
                        Label = "Hyperviseur actif", Detail = "virtualisation presente",
                        Evidence = o["Manufacturer"] + " " + o["Model"] });
            }
        } catch { }
        try { using var s = new ManagementObjectSearcher("SELECT SerialNumber FROM Win32_BIOS"); foreach (ManagementObject o in s.Get()) r.Data["bios_serie"] = o["SerialNumber"]?.ToString(); } catch { }
        try {
            using var s = new ManagementObjectSearcher("SELECT Model, SerialNumber FROM Win32_DiskDrive");
            var l = new List<string>();
            foreach (ManagementObject o in s.Get()) l.Add(o["Model"] + " / " + o["SerialNumber"]);
            r.Data["disques"] = l;
        } catch { }
    }
}
