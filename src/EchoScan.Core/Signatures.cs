using System.Reflection;
using System.Text.Json;

namespace EchoScan.Core;

public class Signature {
    public string Name { get; set; }
    public string Category { get; set; }
    public int Severity { get; set; }
    public string Label { get; set; }
}

public static class SignatureDb {
    static List<Signature> cache;
    public static List<Signature> All {
        get {
            if (cache != null) return cache;
            cache = new List<Signature>();
            try {
                var asm = Assembly.GetExecutingAssembly();
                var name = asm.GetManifestResourceNames().FirstOrDefault(n => n.EndsWith("signatures.json"));
                if (name is null) return cache;
                using var s = asm.GetManifestResourceStream(name);
                using var r = new StreamReader(s);
                cache = JsonSerializer.Deserialize<List<Signature>>(r.ReadToEnd(), new JsonSerializerOptions { PropertyNameCaseInsensitive = true }) ?? cache;
            } catch { }
            return cache;
        }
    }
    public static Signature Match(string text) {
        if (string.IsNullOrWhiteSpace(text)) return null;
        var l = text.ToLowerInvariant().Trim();
        return All.FirstOrDefault(s => l == s.Name || l.StartsWith(s.Name + ".") || l.StartsWith(s.Name + "_") || l.StartsWith(s.Name + "-") || l.StartsWith(s.Name + " "));
    }
}

