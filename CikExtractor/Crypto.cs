using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;

namespace CikExtractor;

internal static class Crypto
{
    internal static byte[] DecryptContentKey(byte[] deviceKey, byte[] encryptedContentKey)
    {
        var engine = new AesWrapEngine();
        engine.Init(false, new KeyParameter(deviceKey));

        return engine.Unwrap(encryptedContentKey, 0, encryptedContentKey.Length);
    }
}