using System.Text;
using System.Text.Json;

namespace EchoScan.Core;

public static class ReportWriter {
    public static string Write(Report r, string dir) {
        Directory.CreateDirectory(dir);
        File.WriteAllText(Path.Combine(dir, "rapport.json"), JsonSerializer.Serialize(r, new JsonSerializerOptions { WriteIndented = true }));
        File.WriteAllText(Path.Combine(dir, "rapport.html"), Html(r), Encoding.UTF8);
        return dir;
    }
    static string Html(Report r) {
        var sb = new StringBuilder();
        sb.AppendLine("<!doctype html><meta charset=utf-8><title>EchoScan</title>");
        sb.AppendLine("<style>body{background:#0a0b0e;color:#e8ebf0;font:13px system-ui;padding:28px}.f{border-left:3px solid #444;background:#15181e;padding:9px 12px;margin:6px 0;border-radius:6px}.s4{border-color:#ef4444}.s3{border-color:#f97316}.s2{border-color:#f59e0b}.s1{border-color:#22c55e}code{color:#8b9bff;font-size:11px}</style>");
        sb.AppendLine("<h1>EchoScan</h1><div>verdict : " + r.Verdict + " (score " + r.Score + ")</div>");
        sb.AppendLine("<div>" + r.Machine + " / " + r.User + " / " + r.Os + "</div><hr>");
        foreach (var f in r.Findings)
            sb.AppendLine("<div class=\