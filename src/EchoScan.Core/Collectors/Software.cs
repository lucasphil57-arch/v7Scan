using Microsoft.Win32;

namespace EchoScan.Core.Collectors;

public static class Software {
    public static void Run(Report r) {
        var list = new List<string>();
        foreach (var hive in new[] { @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall" })
            try {
                using var k = Registry.LocalMachine.OpenSubKey(hive);
                foreach (var n in k?.GetSubKeyNames() ?? Array.Empty<string>())
                    using (var s = k.OpenSubKey(n)) {
                        var name = s?.GetValue("DisplayName")?.ToString();
                        if (!string.IsNullOrWhiteSpace(name)) list.Add(name);
                    }
            } catch { }
        list = list.Distinct().OrderBy(x => x).ToList();
        r.Data["logiciels"] = list;
        foreach (var n in list)
            if (SignatureDb.Match(n) is { } s)
                r.Findings.Add(new Finding { Collector = "logiciels", Category = s.Category,
                    Severity = (Severity)s.Severity, Label = s.Label + " installe", Detail = n });
        try { foreach (var f in Directory.GetFiles(@"C:\Windows\Prefetch", "*.pf").Take(4000))
            if (SignatureDb.Match(Path.GetFileNameWithoutExtension(f)) is { } s)
                r.Findings.Add(new Finding { Collector = "prefetch", Category = s.Category,
                    Severity = (Severity)Math.Max(1, s.Severity - 1), Label = s.Label + " a deja tourne",
                    Detail = "preuve d execution", Evidence = f }); } catch { }
    }
}