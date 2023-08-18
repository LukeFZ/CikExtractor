using System.Diagnostics;
using CikExtractor.Models;
using Registry;

namespace CikExtractor;

internal sealed class RegistryManager
{
    private const string RegExe = "reg";
    private const string ControlRegKey = @"HKLM\SYSTEM\ControlSet001\Control\";

    private const string ExportCommand = "save {0} \"{1}\" /Y";

    // Registry Constants
    private const string RootClipStoragePath = "{7746D80F-97E0-4E26-9543-26B41FC22F79}";
    private const string LicenseBlobStorage = $"{RootClipStoragePath}\\{{A25AE4F2-1B96-4CED-8007-AA30E9B1A218}}";

    // Unused here, just for reference
    private const string LicenseContentKeyIdStorage = $"{RootClipStoragePath}\\{{D73E01AC-F5A0-4D80-928B-33C1920C38BA}}";
    private const string LicencePolicyKeyStorage = $"{RootClipStoragePath}\\{{59AEE675-B203-4D61-9A1F-04518A20F359}}";
    private const string LicenseEntryIdStorage = $"{RootClipStoragePath}\\{{FB9F5B62-B48B-45F5-8586-E514958C92E2}}";
    private const string OptionalInfoStorage = $"{RootClipStoragePath}\\{{221601AB-48C7-4970-B0EC-96E66F578407}}";

    private RegistryHive? _loadedRegistry;

    public IEnumerable<SpLicense> Licenses
    {
        get
        {
            Debug.Assert(_loadedRegistry != null, "_loadedRegistry != null");
            return _licenses ??= ParseLicenses();
        }
    }

    private List<SpLicense>? _licenses;

    public bool LoadLicenses(string? hivePath = null)
    {
        if (hivePath == null)
        {
            hivePath = Path.GetTempFileName();

            ExportRegistryHive(ControlRegKey, hivePath);
        }

        return LoadHive(hivePath);
    }

    public void ExportHive(string path)
    {
        ExportRegistryHive(ControlRegKey, path);
    }

    private bool LoadHive(string hivePath)
    {
        _loadedRegistry = new RegistryHive(hivePath);
        return _loadedRegistry.ParseHive();
    }

    private static void ExportRegistryHive(string hiveName, string outputPath)
    {
        using var process = new Process();
        process.StartInfo.Verb = "runas";
        process.StartInfo.FileName = RegExe;
        process.StartInfo.CreateNoWindow = true;
        process.StartInfo.UseShellExecute = true;
        process.StartInfo.Arguments = string.Format(ExportCommand, hiveName, outputPath);

        process.Start();
        process.WaitForExit();
    }

    private List<SpLicense> ParseLicenses()
    {
        Debug.Assert(_loadedRegistry != null, "_loadedRegistry != null");

        var licenseBlobValues = _loadedRegistry.GetKey(LicenseBlobStorage).Values;
        return licenseBlobValues
            .Where(value => value.ValueDataRaw.Length > 8)
            .Select(licenseBlobValue => licenseBlobValue.ValueDataRaw)
            .Select(licenseBlob => new SpLicense(licenseBlob))
            .ToList();
    }
}