using System.Diagnostics;

namespace CikExtractor;

internal static class DeviceKeyDumper
{
    private const string Python = "python";
    private const string ErrorPrefix = "Error";

    private const string EmulationDir = "Emulation";

    private const string DllName = "clipsp.sys";
    private const string DllTargetPath = $"{EmulationDir}/{DllName}";
    private const string DllSourcePath = $"C:/Windows/System32/drivers/{DllName}";

    private const string KernelName = "ntoskrnl.exe";
    private const string KernelSourcePath = $"C:/Windows/System32/{KernelName}";
    private const string KernelTargetDirectory = $"{EmulationDir}/x8664_windows/Windows/System32";
    private const string KernelTargetPath = $"{KernelTargetDirectory}/{KernelName}";

    public static byte[]? DeriveDeviceKey(DeviceKeyParameters parameters)
    {
        if (!File.Exists(KernelTargetPath))
        {
            Directory.CreateDirectory(KernelTargetDirectory);
            File.Copy(KernelSourcePath, KernelTargetPath);
        }

        if (!File.Exists(DllTargetPath))
            File.Copy(DllSourcePath, DllTargetPath);

        using var process = new Process();
        process.StartInfo.FileName = Python;
        process.StartInfo.CreateNoWindow = false;
        process.StartInfo.RedirectStandardOutput = true;
        process.StartInfo.Arguments = parameters.ToCommand();
        process.StartInfo.WorkingDirectory = Path.GetFullPath(EmulationDir);

        process.Start();
        process.WaitForExit();

        var deviceKey = process.StandardOutput.ReadLine()!.Trim();

        if (deviceKey.Contains(ErrorPrefix))
        {
            Console.WriteLine(deviceKey);
            return null;
        }

        return Convert.FromHexString(deviceKey.Trim());
    }
}