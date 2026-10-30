using System.IO.Compression;
using EchoScan.Core;

Console.Title = "EchoScan";
Console.WriteLine();
Console.WriteLine("  EchoScan 1.0");
Console.WriteLine("  lecture locale, aucun envoi reseau, pas d administrateur.");
Console.WriteLine();
Console.Write("  Lancer ? [O/n] ");
if ((Console.ReadLine() ?? "").Trim().ToLower() is "n" or "non") return;
Console.WriteLine();
var report = Scanner.Run(Console.WriteLine);
var dir = Path.Combine(Path.GetTempPath(), "echoscan_" + Guid.NewGuid().ToString("N")[..8]);
ReportWriter.Write(report, dir);
var zip = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), "EchoScan_" + Environment.MachineName + "_" + DateTime.Now.ToString("yyyyMMdd_HHmmss") + ".zip");
ZipFile.CreateFromDirectory(dir, zip);
Directory.Delete(dir, true);
Console.WriteLine();
Console.WriteLine("  verdict : " + report.Verdict + " (score " + report.Score + ")");
foreach (var f in report.Findings.Take(12)) Console.WriteLine("   [" + f.Severity + "] " + f.Label);
Console.WriteLine();
Console.WriteLine("  rapport : " + zip);
try { System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("explorer.exe", "/select,\"" + zip + "\"")); } catch { }
Console.Write("  Entree pour fermer ");
Console.ReadLine();