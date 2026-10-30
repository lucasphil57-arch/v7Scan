using System.Security.Principal;
using EchoScan.Core.Collectors;

namespace EchoScan.Core;

public static class Scanner {
    public static Report Run(Action<string> step = null) {
        var r = new Report { Machine = Environment.MachineName, User = Environment.UserName,
            Os = Environment.OSVersion.VersionString,
            Admin = new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator) };
        void S(string m) { try { step?.Invoke(m); } catch { } }
        S("bus PCI et materiel"); Safe(() => Hardware.Run(r));
        S("pilotes et modules noyau"); Safe(() => Drivers.Run(r));
        S("processus"); Safe(() => Processes.Run(r));
        S("logiciels installes"); Safe(() => Software.Run(r));
        S("artefacts FiveM"); Safe(() => FiveM.Run(r));
        r.Findings = r.Findings.GroupBy(f => f.Label + "|" + f.Evidence).Select(g => g.First())
            .OrderByDescending(f => f.Severity).ToList();
        return r;
    }
    static void Safe(Action a) { try { a(); } catch { } }
}