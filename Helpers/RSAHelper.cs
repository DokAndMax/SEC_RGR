using System.Security.Cryptography;

namespace Helpers;

public class RSAHelper
{
    private readonly RSA _rsa = RSA.Create(2048);

    public string GetPublicKey()
    {
        return Convert.ToBase64String(_rsa.ExportRSAPublicKey());
    }

    public byte[] DecryptData(byte[] encryptedData)
    {
        return _rsa.Decrypt(encryptedData, RSAEncryptionPadding.Pkcs1);
    }

    public byte[] EncryptData(byte[] data, string base64PublicKey)
    {
        using var rsaEncrypt = RSA.Create();
        rsaEncrypt.ImportRSAPublicKey(Convert.FromBase64String(base64PublicKey), out _);
        return rsaEncrypt.Encrypt(data, RSAEncryptionPadding.Pkcs1);
    }
}