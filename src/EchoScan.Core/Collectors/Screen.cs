using System.Drawing;
using System.Drawing.Imaging;
using System.Runtime.InteropServices;

namespace EchoScan.Core.Collectors;

public static class Screen {
    [DllImport("user32.dll")] static extern int GetSystemMetrics(int i);

    public static void Run(Report r, string dir) {
        try {
            var w = GetSystemMetrics(0);
            var h = GetSystemMetrics(1);
            if (w <= 0 || h <= 0) return;
            using var bmp = new Bitmap(w, h);
            using (var g = Graphics.FromImage(bmp)) g.CopyFromScreen(0, 0, 0, 0, new Size(w, h));
            var path = Path.Combine(dir, "ecran.png");
            bmp.Save(path, ImageFormat.Png);
            r.Data["capture"] = path;
        } catch { }
    }
}
