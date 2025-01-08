using System.Security.Cryptography;

namespace Helpers;

public class AESHelper
{
    public static byte[] EncryptWithAES(byte[] data, byte[] key)
    {
        using var aes = Aes.Create();
        aes.Key = key;
        aes.GenerateIV();
        using ICryptoTransform encryptor = aes.CreateEncryptor();
        using var ms = new MemoryStream();
        ms.Write(aes.IV, 0, aes.IV.Length);
        using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
        {
            cs.Write(data, 0, data.Length);
            cs.FlushFinalBlock();
        }
        return ms.ToArray();
    }

    public static byte[] DecryptWithAES(byte[] encryptedData, byte[] key)
    {
        using var aes = Aes.Create();
        aes.Key = key;
        var iv = new byte[16];
        Array.Copy(encryptedData, 0, iv, 0, iv.Length);
        aes.IV = iv;
        using ICryptoTransform decryptor = aes.CreateDecryptor();
        using var ms = new MemoryStream();
        using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Write))
        {
            cs.Write(encryptedData, iv.Length, encryptedData.Length - iv.Length);
            cs.FlushFinalBlock();
        }
        return ms.ToArray();
    }
}