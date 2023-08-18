using System.Text;

namespace CikExtractor.Models;

public class SpLicense
{
    public readonly string PackageName = "";
    public readonly ushort LicenseVersion;
    public readonly LicenseType LicenseType;
    public readonly BasicPolicies? BasicPolicies;

    public readonly DateTimeOffset? PollingTime;
    public readonly DateTimeOffset? IssuedTime;
    public readonly DateTimeOffset? ExpirationTime;

    public readonly byte[]? DeviceId;
    public readonly Guid? LicenseId;
    public readonly byte[]? HardwareId;
    public readonly byte[]? UplinkKeyId;

    public readonly Guid? KeyholderKeyLicenseId;
    public readonly byte[]? KeyholderPublicSigningKey;

    public readonly List<byte[]> EntryIds = new();
    public readonly Dictionary<Guid, byte[]> PackedContentKeys = new();
    public readonly byte[]? EncryptedDeviceKey;

    public readonly byte[]? LicensePolicies;
    public readonly byte[]? KeyholderPolicies;

    public readonly ushort SignatureOrigin;
    public readonly byte[]? SignatureBlock;
    public readonly byte[]? ClepSignState;

    public readonly byte[]? UnknownBlock2;

    public SpLicense(byte[] licenseBlob)
    {
        using var reader = new BinaryReader(new MemoryStream(licenseBlob));

        var header = reader.ReadBytes(4);
        var sigBlockOffset = reader.ReadUInt32();

        while (reader.BaseStream.Position != reader.BaseStream.Length)
        {
            var blockId = (SpLicenseBlocks) reader.ReadInt32();

            var blockLength = reader.ReadInt32();

            switch (blockId)
            {
                case SpLicenseBlocks.LicenseId:
                    LicenseId = new Guid(reader.ReadBytes(16));
                    break;

                case SpLicenseBlocks.ClepSignState:
                    ClepSignState = reader.ReadBytes(blockLength);
                    break;

                case SpLicenseBlocks.KeyholderKeyLicenseId:
                    KeyholderKeyLicenseId = new Guid(reader.ReadBytes(16));
                    break;

                case SpLicenseBlocks.KeyholderPublicSigningKey:
                    KeyholderPublicSigningKey = reader.ReadBytes(blockLength);
                    break;

                case SpLicenseBlocks.KeyholderPolicies:
                    KeyholderPolicies = reader.ReadBytes(blockLength);
                    break;

                case SpLicenseBlocks.LicensePolicies:
                    LicensePolicies = reader.ReadBytes(blockLength);
                    break;

                case SpLicenseBlocks.UplinkKeyId:
                    UplinkKeyId = reader.ReadBytes(blockLength);
                    break;

                case SpLicenseBlocks.DeviceLicenseDeviceId: // 0xa
                case SpLicenseBlocks.LicenseDeviceId: // 0x8
                    DeviceId = reader.ReadBytes(blockLength);
                    break;

                case SpLicenseBlocks.UnkBlock2:
                    UnknownBlock2 = reader.ReadBytes(blockLength);
                    break;

                case SpLicenseBlocks.HardwareId:
                    HardwareId = reader.ReadBytes(blockLength);
                    break;

                case SpLicenseBlocks.PackageFullName:
                    PackageName = Encoding.Unicode.GetString(reader.ReadBytes(blockLength))[..^1];
                    break;

                case SpLicenseBlocks.SignatureBlock:
                    var unk = reader.ReadUInt16();
                    SignatureOrigin = reader.ReadUInt16();
                    SignatureBlock = reader.ReadBytes(blockLength);
                    break;

                case SpLicenseBlocks.EncryptedDeviceKey:
                    reader.BaseStream.Seek(2, SeekOrigin.Current);
                    EncryptedDeviceKey = reader.ReadBytes(blockLength - 2);
                    break;
                
                case SpLicenseBlocks.LicenseExpirationTime:
                case SpLicenseBlocks.DeviceLicenseExpirationTime:
                    ExpirationTime = DateTimeOffset.FromUnixTimeSeconds(reader.ReadInt32());
                    break;

                case SpLicenseBlocks.LicenseInformation:
                    LicenseVersion = reader.ReadUInt16();
                    LicenseType = (LicenseType) reader.ReadUInt16();
                    IssuedTime = DateTimeOffset.FromUnixTimeSeconds(reader.ReadInt32());
                    BasicPolicies = (BasicPolicies) reader.ReadUInt16();
                    break;

                case SpLicenseBlocks.LicenseEntryIds:
                    var count = reader.ReadUInt16();
                    for (int i = 0; i < count; i++)
                        EntryIds.Add(reader.ReadBytes(32));
                    break;

                case SpLicenseBlocks.PackedContentKeys:
                    var currentOffset = 0;
                    while (currentOffset != blockLength)
                    {
                        var keyIdLen = reader.ReadUInt16(); // 0x20
                        var packedKeyLen = reader.ReadUInt16(); // 0x28

                        var keyId = reader.ReadBytes(keyIdLen);
                        var packedKey = reader.ReadBytes(packedKeyLen);

                        PackedContentKeys.Add(new Guid(keyId[..16]), packedKey);

                        currentOffset += 4 + keyIdLen + packedKeyLen;
                    }
                    break;

                case SpLicenseBlocks.PollingTime:
                    PollingTime = DateTimeOffset.FromUnixTimeSeconds(reader.ReadInt32());
                    break;

                case SpLicenseBlocks.UnkBlock0:
                case SpLicenseBlocks.UnkBlock1:
                case SpLicenseBlocks.UnkBlock3:
                case SpLicenseBlocks.UnkBlock4:
                case SpLicenseBlocks.UnkBlock5:
                default:
                    Console.WriteLine($"Parsing block id {blockId} ({blockId:X}) is not implemented.");
                    reader.BaseStream.Seek(blockLength, SeekOrigin.Current);
                    break;
            }
        }
    }
}