using System.Diagnostics;
using System.Management;

namespace CikExtractor;

internal static class DeviceKeyDumper
{
    public static byte[]? DumpDeviceKey(byte[] encryptedLicense)
    {
        var smbios = DumpSmbios();

        return 
            smbios == null
                ? null 
                : DeriveDeviceKey(smbios, new byte[] {0x0}, encryptedLicense);
    }

    private const string Python = "python";
    private const string ErrorPrefix = "Error";
    private const string DllName = "clipsp.sys";
    private const string EmulationDir = "Emulation";
    private const string KernelFilename = "ntoskrnl.exe";
    private const string DllTargetPath = $"{EmulationDir}/{DllName}";
    private const string DllSourcePath = $"C:/Windows/System32/drivers/{DllName}";
    private const string KernelWindowsPath = $"C:/Windows/System32/{KernelFilename}";
    private const string System32Dir = $"{EmulationDir}/x8664_windows/Windows/System32";
    private const string RegistryPath = $"{EmulationDir}/x8664_windows/Windows/registry";
    private const string CommandTemplate = "clep_vault.py --license \"{0}\" --smbios \"{1}\" --driveser \"{2}\"";

    private const string BaseHiveName = "HKLM";
    private const string DefaultUserHive = @"C:\Users\Default\NTUSER.DAT";
    private static readonly string[] HiveNames = {
        "SYSTEM", "SECURITY", "SOFTWARE", "HARDWARE", "SAM"
    };

    private static byte[]? DeriveDeviceKey(byte[] smbios, byte[] driveSerial, byte[] encryptedLicense)
    {
        var kernelPath = Path.Join(Directory.GetCurrentDirectory(), System32Dir, KernelFilename);
        if (!File.Exists(kernelPath))
        {
            Directory.CreateDirectory(Path.Join(Directory.GetCurrentDirectory(), System32Dir));
            File.Copy(KernelWindowsPath, kernelPath);
        }

        if (!File.Exists(DllTargetPath))
            File.Copy(DllSourcePath, DllTargetPath);

        if (!Directory.Exists(RegistryPath))
        {
            Directory.CreateDirectory(RegistryPath);
            foreach (var hive in HiveNames)
                RegistryInterface.ExportRegistryHive($"{BaseHiveName}\\{hive}", Path.Join(RegistryPath, hive));

            File.Copy(DefaultUserHive, Path.Join(RegistryPath, "NTUSER.DAT"));
        }

        var smbiosB64 = Convert.ToBase64String(smbios);
        var driveB64 = Convert.ToBase64String(driveSerial);
        var licenseB64 = Convert.ToBase64String(encryptedLicense);

        using var process = new Process();
        process.StartInfo.FileName = Python;
        process.StartInfo.CreateNoWindow = false;
        process.StartInfo.RedirectStandardOutput = true;
        process.StartInfo.Arguments = string.Format(CommandTemplate, licenseB64, smbiosB64, driveB64);
        process.StartInfo.WorkingDirectory = Path.Join(Directory.GetCurrentDirectory(), EmulationDir);

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


    private static byte[]? DumpSmbios()
    {
        var mgmtScope = new ManagementScope(@"\\localhost\root\WMI");
        mgmtScope.Connect();

        var query = new ObjectQuery("SELECT * FROM MSSmBios_RawSMBiosTables");
        var searcher = new ManagementObjectSearcher(mgmtScope, query);
        var collection = searcher.Get();
        foreach (var entry in collection)
        {
            if (entry?["SMBiosData"] is byte[] rawData)
                return GetSystemStructFromRawSmbios(rawData);
        }

        return null;
    }

    private static byte[]? GetSystemStructFromRawSmbios(byte[] raw)
    {
        var len = raw.Length;
        var current = 0;
        var isSystemStruct = false;
        byte[]? systemStructData = null;

        while (current < len)
        {
            var tableId = raw[current];
            var formattedLen = raw[current + 1];
            var handle = BitConverter.ToUInt16(raw, current + 2);

            var tableData = raw.Skip(current).Take(formattedLen).ToArray();

            current += formattedLen;

            if (tableId == 0x1)
            {
                isSystemStruct = true;
                systemStructData = tableData;
            }

            var unformattedLen = current;

            while (raw[unformattedLen] != 0x0 || raw[unformattedLen + 1] != 0x0)
                unformattedLen++;

            unformattedLen += 2;

            if (unformattedLen - current != 0)
            {
                var unformattedData = raw.Skip(current).Take(unformattedLen - current).ToArray();
                if (isSystemStruct && systemStructData != null)
                {
                    var newBuf = new byte[systemStructData.Length + unformattedData.Length];
                    Buffer.BlockCopy(systemStructData, 0, newBuf, 0, systemStructData.Length);
                    Buffer.BlockCopy(unformattedData, 0, newBuf, systemStructData.Length, unformattedData.Length);

                    return newBuf.Length > 256 ? newBuf.Take(256).ToArray() : newBuf;
                }
            }

            current = unformattedLen;
        }

        Console.WriteLine("Could not find system struct in SMBIOS.");
        return null;
    }

    /*
     Technically, this is also used for deriving/decrypting the device key. But testing showed that is not actually used, at least in all cases I've observed.
     
    private static byte[]? DumpDriveSerial()
    {
        var rootInfo = new DriveInfo("C");
        var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_DiskDrive WHERE DeviceID = \"\\\\\\\\.\\\\PHYSICALDRIVE0\"");

        foreach (var entry in searcher.Get())
        {
            var serialNo = entry["SerialNumber"] as string;
            var serialNoBuf = Encoding.UTF8.GetBytes(serialNo + '\x00');
            return serialNoBuf.Length > 64 ? serialNoBuf.Take(64).ToArray() : serialNoBuf;
        }

        Console.WriteLine("Could not get root drive serial number.");
        return null;
    }

    */
}