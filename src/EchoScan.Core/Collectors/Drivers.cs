using System.ServiceProcess;
using Microsoft.Win32;

namespace EchoScan.Core.Collectors;

public static class Drivers {
    public static void Run(Report r) {
        var signed = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try {
            foreach (var s in ServiceController.GetServices())
                try {
                    using var k = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\" + s.ServiceName);
                    var img = k?.GetValue("ImagePath")?.ToString();
                    if (string.IsNullOrWhiteSpace(img)) continue;
                    var full = Resolve(img);
                    if (full is null || !File.Exists(full)) continue;
                    var name = Path.GetFileName(full);
                    if (Native.IsSigned(full)) { signed.Add(name); continue; }
                    if (!seen.Add(name)) continue;
                    var system = full.Contains(@"\Windows\", StringComparison.OrdinalIgnoreCase);
                    r.Findings.Add(new Finding {
                        Collector = "drivers", Category = "kernel", Severity = Severity.Low,
                        Label = system ? "Pilote non signe (systeme)" : "Pilote non signe (editeur tiers)",
                        Detail = s.DisplayName, Evidence = full });
                } catch { }
        } catch { }
        foreach (var (path, _, _) in Native.KernelModules()) {
            var name = Path.GetFileName(path);
            if (signed.Contains(name)) continue;
            if (SignatureDb.Match(name) is { } sig)
                r.Findings.Add(new Finding { Collector = "drivers", Category = sig.Category,
                    Severity = (Severity)sig.Severity, Label = "Module noyau connu : " + sig.Label,
                    Detail = "charge en memoire", Evidence = path });
        }
        try {
            using var k = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\SystemStartOptions");
            var opt = k?.GetValue(null)?.ToString() ?? "";
            r.Data["options_demarrage"] = opt;
            if (opt.Contains("TESTSIGNING", StringComparison.OrdinalIgnoreCase))
                r.Findings.Add(new Finding { Collector = "drivers", Category = "kernel", Severity = Severity.High,
                    Label = "Mode TESTSIGNING actif", Detail = "signature de pilotes non verifiee", Evidence = opt });
        } catch { }
    }

    static string Resolve(string img) {
        var p = Environment.ExpandEnvironmentVariables(img.Trim((char)34)).Trim();
        if (p.StartsWith(@"\??\")) p = p[4..];
        if (p.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase))
            p = Path.Combine(Environment.SystemDirectory, p[12..]);
        else if (!Path.IsPathRooted(p))
            p = Path.Combine(Environment.SystemDirectory, p);
        return p;
    }
}
