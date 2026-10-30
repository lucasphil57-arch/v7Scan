using System.Diagnostics;

namespace EchoScan.Core.Collectors;

public static class Network {
    static string Sh(string file, string args) {
        try {
            var psi = new ProcessStartInfo(file, args) { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
            using var p = Process.Start(psi);
            var o = p.StandardOutput.ReadToEnd();
            p.WaitForExit(4000);
            return o;
        } catch { return ""; }
    }

    public static void Run(Report r) {
        var arp = Sh("arp", "-a");
        r.Data["arp"] = arp.Split((char)10).Select(l => l.Trim()).Where(l => l.Length > 0).Take(120).ToList();
        var dns = Sh("ipconfig", "/displaydns");
        var names = dns.Split((char)10).Select(l => l.Trim())
            .Where(l => l.StartsWith("Nom", StringComparison.OrdinalIgnoreCase) || l.StartsWith("Record Name", StringComparison.OrdinalIgnoreCase))
            .Select(l => l[(l.IndexOf(":") + 1)..].Trim()).Where(l => l.Length > 2).Distinct().Take(200).ToList();
        r.Data["dns"] = names;
        foreach (var n in names)
            if (SignatureDb.Match(n) is { } s)
                r.Findings.Add(new Finding { Collector = "reseau", Category = s.Category,
                    Severity = (Severity)s.Severity, Label = "Domaine connu resolu : " + s.Label,
                    Detail = n });
    }
}
