namespace EchoScan.Core.Collectors;

public static class FiveM {
    static string Root => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "FiveM");
    static string App => Path.Combine(Root, "FiveM.app");
    public static void Run(Report r) {
        r.Data["fivem_present"] = Directory.Exists(Root);
        if (!Directory.Exists(Root)) return;
        var plugins = Path.Combine(App, "plugins");
        if (Directory.Exists(plugins))
            foreach (var f in Directory.GetFiles(plugins)) {
                var n = Path.GetFileName(f);
                var s = SignatureDb.Match(n);
                r.Findings.Add(new Finding { Collector = "fivem", Category = s?.Category ?? "plugin",
                    Severity = s is null ? Severity.Low : (Severity)s.Severity,
                    Label = "Plugin FiveM : " + n, Detail = "charge par le client", Evidence = f });
            }
        foreach (var proxy in new[] { "d3d11.dll", "dxgi.dll", "d3d9.dll", "version.dll", "winmm.dll" }) {
            var f = Path.Combine(App, proxy);
            if (File.Exists(f))
                r.Findings.Add(new Finding { Collector = "fivem", Category = "proxy", Severity = Severity.High,
                    Label = "DLL proxy dans FiveM", Detail = proxy + " (injection possible)", Evidence = f });
        }
        var logs = Path.Combine(App, "logs", "CitizenFX.log");
        if (File.Exists(logs))
            try {
                var lines = File.ReadAllLines(logs).Reverse().Take(400).ToList();
                r.Data["citizenfx_extraits"] = lines.Take(120).ToList();
                foreach (var l in lines)
                    if (SignatureDb.Match(l) is { } s)
                        r.Findings.Add(new Finding { Collector = "fivem", Category = s.Category,
                            Severity = (Severity)s.Severity, Label = "Trace dans CitizenFX.log : " + s.Label,
                            Detail = l.Length > 160 ? l[..160] : l, Evidence = logs });
            } catch { }
        foreach (var root in new[] { "C:\\", Environment.GetFolderPath(Environment.SpecialFolder.Desktop) })
            try { foreach (var f in Directory.GetFiles(root, "*pcileech*"))
                r.Findings.Add(new Finding { Collector = "fivem", Category = "dma", Severity = Severity.Critical,
                    Label = "Binaire PCILeech", Detail = "outil DMA present", Evidence = f }); } catch { }
    }
}
