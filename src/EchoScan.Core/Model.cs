namespace EchoScan.Core;

public enum Severity { Info = 0, Low = 1, Medium = 2, High = 3, Critical = 4 }

public class Finding {
    public string Collector { get; set; }
    public string Label { get; set; }
    public string Detail { get; set; }
    public string Evidence { get; set; }
    public Severity Severity { get; set; }
    public string Category { get; set; }
}

public class Report {
    public string Version { get; set; } = "1.0.0";
    public DateTime StartedUtc { get; set; } = DateTime.UtcNow;
    public string Machine { get; set; }
    public string User { get; set; }
    public string Os { get; set; }
    public bool Admin { get; set; }
    public Dictionary<string, object> Data { get; set; } = new();
    public List<Finding> Findings { get; set; } = new();
    public int Score => Findings.Where(f => f.Severity >= Severity.Medium).Sum(f => (int)f.Severity);
    public string Verdict => Score switch { 0 => "clean", <= 4 => "douteux", <= 10 => "suspect", _ => "compromis" };
}
