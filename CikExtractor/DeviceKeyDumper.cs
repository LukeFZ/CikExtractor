using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace CikExtractor;

internal static class DeviceKeyDumper
{
    public static byte[] DeriveDeviceKey(DeviceKeyParameters parameters)
    {
        // :)

        if (BinaryPrimitives.ReadUInt32LittleEndian(parameters.EncryptedLicense) != 4)
            throw new InvalidOperationException("Only version 4 device licenses are supported.");

        var encryptedDecryptionKeySchedule = parameters.EncryptedLicense.AsSpan(0x4, 0xe4);
        var encryptedRoundKeys = MemoryMarshal.Cast<byte, uint>(encryptedDecryptionKeySchedule);
        var encryptedDeviceKey = parameters.EncryptedLicense.AsSpan(0x204, 0x10);

        var decryptionKey = (stackalloc byte[16]);
        var decryptionKeyInts = MemoryMarshal.Cast<byte, uint>(decryptionKey);

        decryptionKeyInts[0] = encryptedRoundKeys[46] ^ encryptedRoundKeys[56] ^ 0xE20DF371 ^ 0xCCB22FE6;
        decryptionKeyInts[1] = encryptedRoundKeys[36] ^ encryptedRoundKeys[47] ^ 0xDF080E39;
        decryptionKeyInts[2] = encryptedRoundKeys[40] ^ encryptedRoundKeys[51] ^ 0x6D09B2F5 ^ 0x2AE17AB9;
        decryptionKeyInts[3] = encryptedRoundKeys[30] ^ encryptedRoundKeys[41] ^ 0x37288CEC;

        var aes = Aes.Create();
        aes.Key = decryptionKey.ToArray();
        var deviceKey = aes.DecryptEcb(encryptedDeviceKey, PaddingMode.None);

        // We could just skip decryption and use the key directly, but this serves as a nice sanity check
        if (!decryptionKey.SequenceEqual(deviceKey))
            throw new InvalidOperationException("Failed to decrypt device key.");

        return deviceKey;
    }
}