using System.ComponentModel;
using System.Diagnostics;
using System.Text.Json;
using Spectre.Console;
using Spectre.Console.Cli;

namespace CikExtractor;

internal class Program
{
    static void Main(string[] args)
    {
        var app = new CommandApp<DumpCommand>();

        app.Configure(ctx =>
        {
            ctx.TrimTrailingPeriods(false);

            ctx.AddCommand<DumpCommand>("dump")
                .WithDescription("Derives the device key and decrypts all CIKs stored in the registry. Default command.");

            ctx.AddCommand<ExportHiveCommand>("export-hive")
                .WithDescription("Export the registry hive containing the CIKs into a file.");

            ctx.AddCommand<ExportParametersCommand>("export-params")
                .WithDescription(
                    "Export the parameters needed to derive a device key.\nUseful if you want to run the key derivation on another device.");

            ctx.AddCommand<DeriveKeyCommand>("derive")
                .WithDescription("Derives a device key from the exported parameters of the 'export-params' command.");
        });

        app.Run(args);
    }
}

internal sealed class DumpCommand : Command<DumpCommand.Settings>
{
    public sealed class Settings : CommandSettings
    {
        [DefaultValue("Cik")]
        [Description("Folder to extract CIKs into.")]
        [CommandOption("-c|--export-cik-path")]
        public string? CikExtractionFolder { get; init; }

        [DefaultValue("deviceKey.txt")]
        [Description("File to read/write device key from/into.")]
        [CommandOption("-d|--device-key-path")]
        public string? DeviceKeyFile { get; init; }

        [Description("Path to an already exported registry hive exported by the 'export-hive' command.")]
        [CommandOption("-r|--reg-hive")]
        public string? RegistryHiveFile { get; init; }
    }

    public override int Execute(CommandContext context, Settings settings)
    {
        Debug.Assert(settings.CikExtractionFolder != null, "settings.CikExtractionFolder != null");
        Debug.Assert(settings.DeviceKeyFile != null, "settings.DeviceKeyFile != null");

        byte[] deviceKey;

        var manager = new RegistryManager();

        string? registryPath;

        if (settings.RegistryHiveFile != null)
        {
            registryPath = Path.GetFullPath(settings.RegistryHiveFile);

            ConsoleLogger.WriteInfoLine($"Loading entries from [white bold]{registryPath}[/]...");
        }
        else
        {
            registryPath = null;

            ConsoleLogger.WriteInfoLine("Loading entries from registry...");
        }

        if (manager.LoadLicenses(registryPath))
        {
            ConsoleLogger.WriteInfoLine("Registry [green bold]loaded[/].");
        }
        else
        {
            ConsoleLogger.WriteErrLine("Failed to load registry.");
            return -1;
        }

        var deviceKeyPath = Path.GetFullPath(settings.DeviceKeyFile);

        if (File.Exists(deviceKeyPath))
        {
            ConsoleLogger.WriteInfoLine($"Reading device key from [white]{deviceKeyPath}[/].");
            var deviceKeyFile = File.ReadAllText(deviceKeyPath);

            Debug.Assert(deviceKeyFile.Length == 32, "deviceKeyFile.Length == 32");
            Debug.Assert(deviceKeyFile.All("0123456789ABCDEFabcdef".Contains), "Device key is not a valid hex string");

            deviceKey = Convert.FromHexString(deviceKeyFile);
            ConsoleLogger.WriteInfoLine("[green bold]Successfully[/] loaded device key from file.");
        }
        else
        {
            ConsoleLogger.WriteInfoLine("Deriving device key...");
            var parameters = DeviceKeyParameters.DumpParameters(manager);
            if (parameters == null)
            {
                ConsoleLogger.WriteErrLine("Failed to dump device key parameters.");
                return -1;
            }

            var key = DeviceKeyDumper.DeriveDeviceKey(parameters);
            if (key == null)
            {
                ConsoleLogger.WriteErrLine("Failed to derive device key.");
                return -1;
            }

            deviceKey = key;

            var hexDeviceKey = Convert.ToHexString(deviceKey);

            ConsoleLogger.WriteInfoLine($"[green bold]Successfully[/] derived device key [white bold]{hexDeviceKey}[/].");

            File.WriteAllText(deviceKeyPath, hexDeviceKey);
        }

        var cikFolderPath = Path.GetFullPath(settings.CikExtractionFolder);
        Directory.CreateDirectory(cikFolderPath);

        var tree = new Tree(":post_office:");
        foreach (var license in manager.Licenses.Where(x => x.PackedContentKeys.Count != 0))
        {
            var packageNode = tree.AddNode($":package: [blue]{license.PackageName}[/]");
            packageNode.AddNode($"[white bold]License Type[/]: [green bold]{license.LicenseType}[/]");

            foreach (var pair in license.PackedContentKeys)
            {
                var contentKey = Crypto.DecryptContentKey(deviceKey, pair.Value);
                var filePath = Path.Join(cikFolderPath, $"{pair.Key}.cik");

                File.WriteAllBytes(filePath,
                    pair.Key
                        .ToByteArray()
                        .Concat(contentKey)
                        .ToArray());

                var keyNode = packageNode.AddNode($":key: [blue]{pair.Key}[/]");
                keyNode.AddNode($"[white bold]Key[/]: [green bold]{Convert.ToHexString(contentKey)}[/]");
            }
        }

        AnsiConsole.Write(tree);

        return 0;
    }

    public override ValidationResult Validate(CommandContext context, Settings settings)
    {
        if (File.Exists(settings.CikExtractionFolder))
            return ValidationResult.Error("CIK extraction path must be a folder.");

        if (File.Exists(settings.DeviceKeyFile))
        {
            var deviceKey = File.ReadAllText(settings.DeviceKeyFile);
            if (deviceKey.Length != 32 || !deviceKey.All("0123456789ABCDEFabcdef".Contains))
                return ValidationResult.Error("Provided device key in file is invalid. Must be 32 hex characters long.");
        }

        if (settings.RegistryHiveFile != null && !File.Exists(settings.RegistryHiveFile))
            return ValidationResult.Error("Supplied registry hive does not exist.");

        return ValidationResult.Success();
    }
}

internal sealed class ExportHiveCommand : Command<ExportHiveCommand.Settings>
{
    public sealed class Settings : CommandSettings
    {
        [Description("Path to export the registry hive into.")]
        [CommandArgument(0, "<path>")]
        public string? ExportPath { get; init; }
    }

    public override int Execute(CommandContext context, Settings settings)
    {
        Debug.Assert(settings.ExportPath != null, "settings.ExportPath != null");

        var manager = new RegistryManager();

        var fullPath = Path.GetFullPath(settings.ExportPath);

        manager.ExportHive(fullPath);

        ConsoleLogger.WriteInfoLine($"[green bold]Successfully[/] exported registry hive into [white]{fullPath}[/]");

        return 0;
    }
}

internal sealed class ExportParametersCommand : Command<ExportParametersCommand.Settings>
{
    public sealed class Settings : CommandSettings
    {
        [Description("Path to export the parameters into.")]
        [CommandArgument(0, "<path>")]
        public string? ExportPath { get; init; }
    }

    public override int Execute(CommandContext context, Settings settings)
    {
        Debug.Assert(settings.ExportPath != null, "settings.ExportPath != null");

        var manager = new RegistryManager();
        ConsoleLogger.WriteInfoLine("Parsing registry entries...");
        if (manager.LoadLicenses())
        {
            ConsoleLogger.WriteInfoLine("Registry [green bold]loaded[/].");
        }
        else
        {
            ConsoleLogger.WriteErrLine("Failed to load registry.");
            return -1;
        }

        var parameters = DeviceKeyParameters.DumpParameters(manager);

        var fullPath = Path.GetFullPath(settings.ExportPath);
        var directory = Path.GetDirectoryName(fullPath);
        if (directory != null)
            Directory.CreateDirectory(directory);

        File.WriteAllText(fullPath, JsonSerializer.Serialize(parameters));

        ConsoleLogger.WriteInfoLine($"[green bold]Successfully[/] exported parameters into [white]{fullPath}[/]");

        return 0;
    }
}

internal sealed class DeriveKeyCommand : Command<DeriveKeyCommand.Settings>
{
    public sealed class Settings : CommandSettings
    {
        [Description("Path to the exported parameters.")]
        [CommandArgument(0, "<path>")]
        public string? ParametersPath { get; init; }

        [DefaultValue("deviceKey.txt")]
        [Description("Path to write the derived device key into.")]
        [CommandArgument(1, "[output path]")]
        public string? DeviceKeyPath { get; init; }
    }

    public override int Execute(CommandContext context, Settings settings)
    {
        Debug.Assert(settings.ParametersPath != null, "settings.ParametersPath != null");
        Debug.Assert(settings.DeviceKeyPath != null, "settings.DeviceKeyPath != null");

        var parameters = JsonSerializer.Deserialize<DeviceKeyParameters>(File.ReadAllText(settings.ParametersPath));
        if (parameters == null)
        {
            ConsoleLogger.WriteErrLine("Failed to deserialize key parameters.");
            return -1;
        }

        ConsoleLogger.WriteInfoLine("Imported parameters.");
        ConsoleLogger.WriteInfoLine("Deriving device key...");

        var key = DeviceKeyDumper.DeriveDeviceKey(parameters);
        if (key == null)
        {
            ConsoleLogger.WriteErrLine("Failed to derive device key.");
            return -1;
        }

        var hexDeviceKey = Convert.ToHexString(key);

        ConsoleLogger.WriteInfoLine($"[green bold]Successfully[/] derived device key [white bold]{hexDeviceKey}[/].");

        var fullKeyPath = Path.GetFullPath(settings.DeviceKeyPath);

        File.WriteAllText(fullKeyPath, hexDeviceKey);

        ConsoleLogger.WriteInfoLine($"[green bold]Successfully[/] wrote device key into [white bold]{fullKeyPath}[/].");

        return 0;
    }

    public override ValidationResult Validate(CommandContext context, Settings settings)
    {
        if (settings.ParametersPath != null && !File.Exists(settings.ParametersPath))
            return ValidationResult.Error("Parameters file does not exist.");

        return ValidationResult.Success();
    }
}