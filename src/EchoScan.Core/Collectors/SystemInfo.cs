using System.Management;
using Microsoft.Win32;

namespace EchoScan.Core.Collectors;

public static class SystemInfo {
    public static void Run(Report r) {
        try {
            using var k = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\SecureBoot\State");
            var sb = k?.GetValue("UEFISecureBootEnabled");
            r.Data["secure_boot"] = sb?.ToString() ?? "inconnu";
            if (sb?.ToString() == "0")
                r.Findings.Add(new Finding { Collector = "systeme", Category = "securite",
                    Severity = Severity.Medium, Label = "Secure Boot desactive",
                    Detail = "demarrage non verifie" });
        } catch { }

        try {
            using var s = new ManagementObjectSearcher(@"root\cimv2\Security\MicrosoftTpm",
                "SELECT SpecVersion, IsEnabled_InitialValue FROM Win32_Tpm");
            foreach (ManagementObject o in s.Get()) {
                r.Data["tpm"] = o["SpecVersion"]?.ToString();
                r.Data["tpm_actif"] = o["IsEnabled_InitialValue"]?.ToString();
            }
        } catch { r.Data["tpm"] = "absent ou inaccessible"; }

        try {
            using var s = new ManagementObjectSearcher("SELECT Name, NumberOfCores, MaxClockSpeed FROM Win32_Processor");
            foreach (ManagementObject o in s.Get())
                r.Data["cpu"] = o["Name"] + " / " + o["NumberOfCores"] + " coeurs / " + o["MaxClockSpeed"] + " MHz";
        } catch { }

        try {
            using var s = new ManagementObjectSearcher("SELECT Capacity, Speed, Manufacturer FROM Win32_PhysicalMemory");
            var l = new List<string>();
            foreach (ManagementObject o in s.Get()) l.Add(o["Capacity"] + " o / " + o["Speed"] + " MHz / " + o["Manufacturer"]);
            r.Data["ram"] = l;
        } catch { }

        try {
            using var s = new ManagementObjectSearcher("SELECT Manufacturer, Product FROM Win32_BaseBoard");
            foreach (ManagementObject o in s.Get()) r.Data["carte_mere"] = o["Manufacturer"] + " " + o["Product"];
        } catch { }

        try {
            using var s = new ManagementObjectSearcher("SELECT Name, DriverVersion FROM Win32_VideoController");
            var l = new List<string>();
            foreach (ManagementObject o in s.Get()) l.Add(o["Name"] + " / pilote " + o["DriverVersion"]);
            r.Data["gpu"] = l;
        } catch { }

        try {
            using var s = new ManagementObjectSearcher("SELECT Name, ScreenWidth, ScreenHeight FROM Win32_DesktopMonitor");
            var l = new List<string>();
            foreach (ManagementObject o in s.Get()) l.Add(o["Name"] + " " + o["ScreenWidth"] + "x" + o["ScreenHeight"]);
            r.Data["ecrans"] = l;
        } catch { }

        try {
            using var s = new ManagementObjectSearcher(@"root\SecurityCenter2", "SELECT DisplayName FROM AntiVirusProduct");
            var l = new List<string>();
            foreach (ManagementObject o in s.Get()) l.Add(o["DisplayName"]?.ToString());
            r.Data["antivirus"] = l;
            if (l.Count == 0)
                r.Findings.Add(new Finding { Collector = "systeme", Category = "securite",
                    Severity = Severity.Low, Label = "Aucun antivirus detecte" });
        } catch { }

        try { r.Data["uptime_heures"] = (int)(TimeSpan.FromMilliseconds(Environment.TickCount64).TotalHours); } catch { }
    }
}
