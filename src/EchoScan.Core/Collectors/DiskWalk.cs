namespace EchoScan.Core.Collectors;

public static class DiskWalk {
    static readonly string[] Skip = { @"\Windows\WinSxS", @"\Windows\servicing", @"\Windows\assembly", @"\$Recycle.Bin", @"\System Volume Information", @"\Windows\Installer", @"\ProgramData\Package Cache", @"\node_modules", @"\.git" };

    public static void Run(Report r) {
        var hits = new List<object>();
        var seen = new HashSet<string>();
        var deadline = DateTime.UtcNow.AddSeconds(240);
        long scanned = 0;

        foreach (var d in DriveInfo.GetDrives()) {
            if (d.DriveType != DriveType.Fixed || !d.IsReady) continue;
            var stack = new Stack<string>();
            stack.Push(d.RootDirectory.FullName);
            while (stack.Count > 0) {
                if (DateTime.UtcNow > deadline) { r.Data["disque_tronque"] = true; break; }
                var path = stack.Pop();
                string[] dirs;
                try { dirs = Directory.GetDirectories(path); } catch { continue; }
                foreach (var sub in dirs) {
                    scanned++;
                    if (Skip.Any(s => sub.Contains(s, StringComparison.OrdinalIgnoreCase))) continue;
                    if (Take(r, hits, seen, sub, true)) continue;
                    stack.Push(sub);
                }
                try {
                    foreach (var file in Directory.GetFiles(path)) {
                        scanned++;
                        if (file.EndsWith(".sys", StringComparison.OrdinalIgnoreCase) || file.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                            Take(r, hits, seen, file, false);
                    }
                } catch { }
            }
        }
        r.Data["disque_dossiers_signes"] = hits;
        r.Data["disque_elements_parcourus"] = scanned;
    }

    static bool Take(Report r, List<object> hits, HashSet<string> seen, string path, bool isDir) {
        var name = Path.GetFileNameWithoutExtension(path);
        if (isDir) name = Path.GetFileName(path);
        var sig = SignatureDb.Match(name);
        if (sig is null || !seen.Add(path)) return false;
        hits.Add(new { chemin = path, label = sig.Label, categorie = sig.Category });
        r.Findings.Add(new Finding {
            Collector = "disque", Category = sig.Category,
            Severity = (Severity)Math.Min(4, sig.Severity + 1),
            Label = (isDir ? "Dossier " : "Fichier ") + sig.Label + " sur le disque",
            Detail = "installation presente", Evidence = path
        });
        return isDir;
    }
}
