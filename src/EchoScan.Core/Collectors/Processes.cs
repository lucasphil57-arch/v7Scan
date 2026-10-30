using System.Diagnostics;

namespace EchoScan.Core.Collectors;

public static class Processes {
    public static void Run(Report r) {
        var list = new List<object>();
        foreach (var p in Process.GetProcesses())
            try {
                var sig = SignatureDb.Match(p.ProcessName);
                if (sig is null) continue;
                string path = "";
                try { path = p.MainModule?.FileName ?? ""; } catch { }
                list.Add(new { p.ProcessName, path });
                r.Findings.Add(new Finding { Collector = "processus", Category = sig.Category,
                    Severity = (Severity)sig.Severity, Label = sig.Label + " en execution",
                    Detail = "processus " + p.ProcessName, Evidence = path });
            } catch { }
        r.Data["processus_signes"] = list;
    }
}