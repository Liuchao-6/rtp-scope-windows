using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Windows.Forms;

[assembly: System.Reflection.AssemblyTitle("超哥话探")]
[assembly: System.Reflection.AssemblyDescription("SIP · RTP 通话分析")]
[assembly: System.Reflection.AssemblyProduct("超哥话探")]
[assembly: System.Reflection.AssemblyVersion("0.10.0.0")]
[assembly: System.Reflection.AssemblyFileVersion("0.10.0.0")]

internal static class Launcher {
    // ProcessStartInfo.Arguments follows Windows command-line quoting, without a shell.
    private static string Quote(string value) {
        StringBuilder b = new StringBuilder("\""); int slashes = 0;
        foreach (char c in value) {
            if (c == '\\') { slashes++; continue; }
            if (c == '"') { b.Append('\\', slashes * 2 + 1); b.Append(c); }
            else { b.Append('\\', slashes); b.Append(c); }
            slashes = 0;
        }
        b.Append('\\', slashes * 2); b.Append('"'); return b.ToString();
    }
    [STAThread]
    private static int Main(string[] args) {
        try {
            string root = AppDomain.CurrentDomain.BaseDirectory;
            string runtime = Path.Combine(root, "runtime", "bin", "javaw.exe");
            string jar = Path.Combine(root, "app", "chaoge-huatan.jar");
            if (!File.Exists(runtime) || !File.Exists(jar)) throw new IOException("请先完整解压文件夹，再运行 ChaogeHuatan.exe。");
            StringBuilder arguments = new StringBuilder("-Xms32m -Xmx1024m -Dfile.encoding=UTF-8 -Dsun.java2d.dpiaware=true -Djava.net.useSystemProxies=true -jar ");
            arguments.Append(Quote(jar)); foreach (string arg in args) { arguments.Append(' '); arguments.Append(Quote(arg)); }
            ProcessStartInfo start = new ProcessStartInfo(runtime, arguments.ToString());
            start.WorkingDirectory = root; start.UseShellExecute = false; start.CreateNoWindow = true;
            using (Process child = Process.Start(start)) {
                if (args.Length > 0 && args[0] == "--diagnostics") { child.WaitForExit(); return child.ExitCode; }
            }
            return 0;
        } catch (Exception error) {
            MessageBox.Show(error.Message, "超哥话探", MessageBoxButtons.OK, MessageBoxIcon.Error); return 1;
        }
    }
}
