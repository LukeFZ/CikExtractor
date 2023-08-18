using System.Management;
using System.Text;
using CikExtractor.Models;

namespace CikExtractor;

internal record DeviceKeyParameters(byte[] Smbios, byte[] DriveSerial, byte[] EncryptedLicense)
{
    public static DeviceKeyParameters? DumpParameters(RegistryManager registryManager)
    {
        var deviceLicenses = registryManager.Licenses.Where(x => x.LicenseType == LicenseType.Device).ToList();

        if (0 >= deviceLicenses.Count)
        {
            ConsoleLogger.WriteErrLine("No device license found.");
            return null;
        }

        if (deviceLicenses.Count > 1)
        {
            ConsoleLogger.WriteErrLine("More than one device license found.");
            return null;
        }

        var license = deviceLicenses.First();

        if (license.EncryptedDeviceKey == null)
        {
            ConsoleLogger.WriteErrLine("Device license did not contain an encrypted device key.");
            return null;
        }

        var smbios = DumpSmbios();

        if (smbios == null)
        {
            ConsoleLogger.WriteErrLine("Failed to dump SMBIOS system struct.");
            return null;
        }

        var driveSerial = DumpDriveSerial();

        if (driveSerial == null)
        {
            ConsoleLogger.WriteErrLine("Failed to read the root drive serial number.");
            return null;
        }

        return new DeviceKeyParameters(smbios, driveSerial, license.EncryptedDeviceKey);
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

    private static byte[]? GetSystemStructFromRawSmbios(ReadOnlySpan<byte> smbios)
    {
        var length = smbios.Length;

        var current = 0;
        byte[]? systemStructData = null;

        while (current < length)
        {
            var tableId = smbios[current];
            var formattedLen = smbios[current + 1];

            if (tableId == 0x1)
            {
                systemStructData = smbios.Slice(current, formattedLen).ToArray();
            }

            current += formattedLen;

            var unformattedLen = current;

            while (smbios[unformattedLen] != 0x0 || smbios[unformattedLen + 1] != 0x0)
                unformattedLen++;

            unformattedLen += 2;

            if (unformattedLen - current != 0 && systemStructData != null)
            {
                var unformattedData = smbios[current..unformattedLen].ToArray();

                var newBuf = new byte[systemStructData.Length + unformattedData.Length];
                Buffer.BlockCopy(systemStructData, 0, newBuf, 0, systemStructData.Length);
                Buffer.BlockCopy(unformattedData, 0, newBuf, systemStructData.Length, unformattedData.Length);

                return newBuf.Length > 256 ? newBuf.Take(256).ToArray() : newBuf;
            }

            current = unformattedLen;
        }

        ConsoleLogger.WriteErrLine("Could not find system struct in SMBIOS.");
        return null;
    }

    //Technically, this is also used for deriving/decrypting the device key. But testing showed that is not actually used, at least in all cases I've observed.
    private static byte[]? DumpDriveSerial()
    {
        var searcher = new ManagementObjectSearcher(@"SELECT * FROM Win32_DiskDrive WHERE DeviceID = ""\\\\.\\PHYSICALDRIVE0""");

        foreach (var entry in searcher.Get())
        {
            var serialNo = entry["SerialNumber"] as string;
            var serialNoBuf = Encoding.UTF8.GetBytes(serialNo + '\x00');
            return serialNoBuf.Length > 64 ? serialNoBuf.Take(64).ToArray() : serialNoBuf;
        }

        ConsoleLogger.WriteErrLine("Could not get root drive serial number.");
        return null;
    }

    private const string CommandTemplate = "clep_vault.py --license \"{0}\" --smbios \"{1}\" --driveser \"{2}\"";

    public string ToCommand()
    {
        return string.Format(CommandTemplate, Convert.ToBase64String(EncryptedLicense), Convert.ToBase64String(Smbios),
            Convert.ToBase64String(DriveSerial));
    }
}