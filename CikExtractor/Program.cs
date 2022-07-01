using CikExtractor.Models;

namespace CikExtractor;

internal class Program
{
    private const string CikCachePath = "./Cik";
    private const string DeviceKeyCache = "deviceKey.txt";

    static void Main(string[] args)
    {
        Console.WriteLine("Parsing registry entries...");
        var appLicenses = RegistryInterface.ParseRegistry();
        Console.WriteLine("Registry loaded.");

        byte[]? deviceKey;

        if (File.Exists(DeviceKeyCache))
        {
            deviceKey = Convert.FromHexString(File.ReadAllText(DeviceKeyCache));
        }
        else
        {
            if (appLicenses.All(license => license.LicenseType != LicenseType.Device))
            {
                Console.WriteLine("Error: Could not find device license in dumped registry.");
                return;
            }

            Console.WriteLine("Deriving device key...");
            deviceKey = DeviceKeyDumper.DumpDeviceKey(appLicenses.First(license => license.LicenseType == LicenseType.Device).EncryptedDeviceKey!);
        }

        if (deviceKey == null)
        {
            Console.WriteLine("Error: Could not derive device key.");
            return;
        }

        var deviceKeyHex = Convert.ToHexString(deviceKey);

        Console.WriteLine($"Device Key loaded! Device Key: {deviceKeyHex}");
        File.WriteAllText(DeviceKeyCache, deviceKeyHex);

        Directory.CreateDirectory(CikCachePath);

        foreach (var license in appLicenses.Where(lic => lic.PackedContentKeys.Count > 0))
        {
            Console.WriteLine($"Package Name: {license.PackageName} | License Type: {license.LicenseType} | Key Count: {license.PackedContentKeys.Count}");

            foreach (var pair in license.PackedContentKeys)
            {
                var contentKey = Crypto.DecryptContentKey(deviceKey, pair.Value);

                Console.WriteLine($"Key Id {pair.Key} | Key: {Convert.ToHexString(contentKey)}");

                var filePath = Path.Join(CikCachePath, $"{pair.Key}.cik");
                var cikData = new byte[16 + contentKey.Length];

                Buffer.BlockCopy(pair.Key.ToByteArray(), 0, cikData, 0, 16);
                Buffer.BlockCopy(contentKey, 0, cikData, 16, contentKey.Length);

                File.WriteAllBytes(filePath, cikData);
            }
        }
    }
}