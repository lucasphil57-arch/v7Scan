using EchoScan.Core;
using Xunit;

public class Tests {
    [Fact] public void Signatures_chargees() => Assert.NotEmpty(SignatureDb.All);
    [Fact] public void Detecte_pcileech() => Assert.NotNull(SignatureDb.Match("pcileech.exe"));
    [Fact] public void Verdict_progresse() { var r = new Report(); Assert.Equal("clean", r.Verdict); r.Findings.Add(new Finding { Severity = Severity.Critical }); Assert.NotEqual("clean", r.Verdict); }
}