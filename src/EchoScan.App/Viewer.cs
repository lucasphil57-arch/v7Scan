using System.Diagnostics;
using System.Drawing;
using System.Windows.Forms;
using EchoScan.Core;

namespace EchoScan.App;

public class Viewer : Form {
    readonly Report report;
    readonly string zip;
    readonly DataGridView grid = new();
    readonly TextBox filter = new();

    public Viewer(Report r, string zipPath) {
        report = r;
        zip = zipPath;
        Text = "EchoScan - revue";
        Width = 1200; Height = 760;
        BackColor = Color.FromArgb(10, 11, 14);
        ForeColor = Color.FromArgb(232, 235, 240);
        Font = new Font("Segoe UI", 9.5f);
        StartPosition = FormStartPosition.CenterScreen;
        Build();
        Fill();
    }

    void Build() {
        var head = new Panel { Dock = DockStyle.Top, Height = 62, BackColor = Color.FromArgb(14, 16, 20) };
        var v = new Label {
            Text = "verdict : " + report.Verdict + "   score " + report.Score + "   " + report.Findings.Count + " constats",
            Left = 14, Top = 10, AutoSize = true, Font = new Font("Segoe UI", 12f, FontStyle.Bold),
            ForeColor = report.Score == 0 ? Color.FromArgb(34, 197, 94) : Color.FromArgb(245, 158, 11)
        };
        var who = new Label {
            Text = report.Machine + " / " + report.User + " / " + report.Os + " / admin " + report.Admin,
            Left = 14, Top = 36, AutoSize = true, ForeColor = Color.FromArgb(120, 131, 143)
        };
        var open = new Button { Text = "Dossier", Left = 900, Top = 14, Width = 120, Height = 30, FlatStyle = FlatStyle.Flat, BackColor = Color.FromArgb(88, 101, 242), ForeColor = Color.White };
        open.Click += (s, e) => Process.Start("explorer.exe", "/select,\"" + zip + "\"");
        var html = new Button { Text = "Rapport HTML", Left = 1030, Top = 14, Width = 130, Height = 30, FlatStyle = FlatStyle.Flat, BackColor = Color.FromArgb(30, 34, 42), ForeColor = Color.FromArgb(232, 235, 240) };
        html.Click += (s, e) => {
            var p = Path.Combine(Path.GetDirectoryName(zip) ?? "", "rapport.html");
            if (File.Exists(p)) Process.Start(new ProcessStartInfo(p) { UseShellExecute = true });
            else Process.Start("explorer.exe", "/select,\"" + zip + "\"");
        };
        head.Controls.AddRange(new Control[] { v, who, open, html });

        filter.Dock = DockStyle.Top;
        filter.PlaceholderText = "filtrer par mot-cle";
        filter.BackColor = Color.FromArgb(20, 23, 29);
        filter.ForeColor = Color.FromArgb(232, 235, 240);
        filter.BorderStyle = BorderStyle.FixedSingle;
        filter.TextChanged += (s, e) => Fill();

        grid.Dock = DockStyle.Fill;
        grid.BackgroundColor = Color.FromArgb(10, 11, 14);
        grid.GridColor = Color.FromArgb(32, 37, 45);
        grid.BorderStyle = BorderStyle.None;
        grid.RowHeadersVisible = false;
        grid.AllowUserToAddRows = false;
        grid.ReadOnly = true;
        grid.AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill;
        grid.SelectionMode = DataGridViewSelectionMode.FullRowSelect;
        grid.DefaultCellStyle.BackColor = Color.FromArgb(20, 23, 29);
        grid.DefaultCellStyle.ForeColor = Color.FromArgb(232, 235, 240);
        grid.DefaultCellStyle.SelectionBackColor = Color.FromArgb(60, 70, 110);
        grid.Columns.Add("sev", "niveau");
        grid.Columns.Add("cat", "categorie");
        grid.Columns.Add("lab", "constat");
        grid.Columns.Add("det", "detail");
        grid.Columns.Add("ev", "preuve");
        grid.Columns[0].FillWeight = 12;
        grid.Columns[1].FillWeight = 14;
        grid.Columns[2].FillWeight = 32;
        grid.Columns[3].FillWeight = 22;
        grid.Columns[4].FillWeight = 42;
        grid.CellDoubleClick += (s, e) => {
            var p = grid.Rows[e.RowIndex].Cells[4].Value?.ToString();
            if (string.IsNullOrWhiteSpace(p)) return;
            try { if (File.Exists(p)) Process.Start("explorer.exe", "/select,\"" + p + "\""); } catch { }
        };

        Controls.Add(grid);
        Controls.Add(filter);
        Controls.Add(head);
    }

    void Fill() {
        var q = filter.Text.Trim().ToLowerInvariant();
        grid.Rows.Clear();
        foreach (var f in report.Findings) {
            if (q.Length > 0) {
                var hay = (f.Label + " " + f.Detail + " " + f.Evidence + " " + f.Category).ToLowerInvariant();
                if (!hay.Contains(q)) continue;
            }
            var i = grid.Rows.Add(f.Severity.ToString(), f.Category, f.Label, f.Detail, f.Evidence);
            grid.Rows[i].DefaultCellStyle.ForeColor = f.Severity switch {
                Severity.Critical => Color.FromArgb(239, 68, 68),
                Severity.High => Color.FromArgb(249, 115, 22),
                Severity.Medium => Color.FromArgb(245, 158, 11),
                Severity.Low => Color.FromArgb(120, 131, 143),
                _ => Color.FromArgb(120, 131, 143)
            };
        }
    }
}
