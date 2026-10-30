using System.Text;
using System.Text.Json;

namespace EchoScan.Core;

public static class ReportWriter {
    const string Q = "\"";

    public static string Write(Report r, string dir) {
        Directory.CreateDirectory(dir);
        File.WriteAllText(Path.Combine(dir, "rapport.json"), JsonSerializer.Serialize(r, new JsonSerializerOptions { WriteIndented = true }));
        File.WriteAllText(Path.Combine(dir, "rapport.html"), Html(r), Encoding.UTF8);
        return dir;
    }

    static string Html(Report r) {
        var sb = new StringBuilder();
        sb.Append("<!doctype html><meta charset=utf-8><title>EchoScan</title>");
        sb.Append("<style>body{background:#0a0b0e;color:#e8ebf0;font:13px system-ui;padding:28px}");
        sb.Append(".f{border-left:3px solid #444;background:#15181e;padding:9px 12px;margin:6px 0;border-radius:6px}");
        sb.Append(".s4{border-color:#ef4444}.s3{border-color:#f97316}.s2{border-color:#f59e0b}.s1{border-color:#22c55e}");
        sb.Append("code{color:#8b9bff;font-size:11px}</style>");
        sb.Append("<h1>EchoScan</h1><div>verdict : " + r.Verdict + " (score " + r.Score + ")</div>");
        sb.Append("<div>" + r.Machine + " / " + r.User + " / " + r.Os + "</div><hr>");
        foreach (var f in r.Findings)
            sb.Append("<div class=" + Q + "f s" + (int)f.Severity + Q + "><b>" + f.Label + "</b><br>" + f.Detail + "<br><code>" + f.Evidence + "</code></div>");
        if (r.Findings.Count == 0) sb.Append("<div class=f>aucune signature connue</div>");
        return sb.ToString();
    }
}
