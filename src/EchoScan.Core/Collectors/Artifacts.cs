using System.Text;
using Microsoft.Win32;

namespace EchoScan.Core.Collectors;

public static class Artifacts {
    static string Rot13(string s) {
        var sb = new StringBuilder(s.Length);
        foreach (var c in s) {
            if (c >= 97 && c <= 122) sb.Append((char)(97 + (c - 97 + 13) % 26));
            else if (c >= 65 && c <= 90) sb.Append((char)(65 + (c - 65 + 13) % 26));
            else sb.Append(c);
        }
        return sb.ToString();
    }

    public static void Run(Report r) {
        foreach (var (hive, path) in new[] {
            (Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (Registry.LocalMachine, @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
            (Registry.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run") })
            try {
                using var k = hive.OpenSubKey(path);
                foreach (var n in k?.GetValueNames() ?? Array.Empty<string>()) {
                    var v = k.GetValue(n)?.ToString() ?? "";
                    r.Data["demarrage_" + n] = v;
                    var sig = SignatureDb.Match(n) ?? SignatureDb.Match(v);
                    if (sig != null) {
                        r.Findings.Add(new Finding { Collector = "demarrage", Category = sig.Category,
                            Severity = (Severity)sig.Severity, Label = sig.Label + " au demarrage",
                            Detail = n, Evidence = v });
                    }
                }
            } catch { }

        try {
            using var k = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Enum\USBSTOR");
            var devs = k?.GetSubKeyNames().ToList() ?? new List<string>();
            r.Data["usb_historique"] = devs;
            foreach (var d in devs)
                if (SignatureDb.Match(d) is { } s)
                    r.Findings.Add(new Finding { Collector = "usb", Category = s.Category,
                        Severity = (Severity)s.Severity, Label = "Peripherique USB " + s.Label,
                        Detail = "deja connecte", Evidence = d });
        } catch { }

        try {
            using var k = Registry.CurrentUser.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist");
            foreach (var g in k?.GetSubKeyNames() ?? Array.Empty<string>())
                using (var c = k.OpenSubKey(g + @"\Count")) {
                    foreach (var n in c?.GetValueNames() ?? Array.Empty<string>()) {
                        var clear = Rot13(n);
                        if (SignatureDb.Match(clear) is { } s)
                            r.Findings.Add(new Finding { Collector = "userassist", Category = s.Category,
                                Severity = (Severity)Math.Max(1, s.Severity - 1),
                                Label = s.Label + " a ete lance", Detail = "historique d execution",
                                Evidence = clear });
                    }
                }
        } catch { }

        try {
            var recent = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Recent));
            r.Data["recents"] = Directory.GetFiles(recent).Select(Path.GetFileNameWithoutExtension).Take(120).ToList();
        } catch { }

        try {
            using var s = new System.Management.ManagementObjectSearcher("SELECT DeviceID, VolumeSerialNumber FROM Win32_LogicalDisk");
            var l = new List<string>();
            foreach (System.Management.ManagementObject o in s.Get()) l.Add(o["DeviceID"] + " " + o["VolumeSerialNumber"]);
            r.Data["volumes"] = l;
        } catch { }
    }
}

