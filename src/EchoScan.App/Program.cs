using System.IO.Compression;
using EchoScan.Core;
using EchoScan.Core.Collectors;

Console.Title = "EchoScan";
Console.WriteLine();
Console.WriteLine("  EchoScan 1.0");
Console.WriteLine("  lecture locale, aucun envoi reseau, pas d administrateur requis.");
Console.WriteLine();
Console.Write("  Lancer ? [O/n] ");
if ((Console.ReadLine() ?? "").Trim().ToLower() is "n" or "non") return;

Console.WriteLine();
var report = Scanner.Run(Console.WriteLine);

var dir = Path.Combine(Path.GetTempPath(), "echoscan_" + Guid.NewGuid().ToString("N")[..8]);
Directory.CreateDirectory(dir);
ReportWriter.Write(report, dir);
Screen.Run(report, dir);

var zip = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
    "EchoScan_" + Environment.MachineName + "_" + DateTime.Now.ToString("yyyyMMdd_HHmmss") + ".zip");
ZipFile.CreateFromDirectory(dir, zip);
Directory.Delete(dir, true);

Console.WriteLine();
Console.ForegroundColor = report.Score == 0 ? ConsoleColor.Green : ConsoleColor.Yellow;
Console.WriteLine("  verdict : " + report.Verdict + " (score " + report.Score + ")");
Console.ResetColor();
foreach (var f in report.Findings.Take(15))
    Console.WriteLine("   [" + f.Severity + "] " + f.Label);
if (report.Findings.Count > 15) Console.WriteLine("   (+" + (report.Findings.Count - 15) + ")");

Console.WriteLine();
Console.WriteLine("  rapport : " + zip);
try { System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("explorer.exe", "/select,\"" + zip + "\"")); } catch { }
Console.Write("  Entree pour fermer ");
Console.ReadLine();
