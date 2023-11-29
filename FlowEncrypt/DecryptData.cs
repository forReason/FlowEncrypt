using System.Security;
using System.Security.Cryptography.X509Certificates;

namespace FlowEncrypt;

public partial class EncryptData
{
    /// <summary>
    /// Decrypts an <see cref="IEnumerable{T}"/>; 
    /// </summary>
    /// <param name="data">The encrypted data to decrypt.</param>
    /// <param name="password">The password used for decryption. Must be the same as the encryption password.</param>
    /// <param name="privateKey">Optional private key for decrypting the salt. Required if the data was encrypted 
    /// with a corresponding public key.</param>
    /// <returns>The decrypted data as a byte array.</returns>
    public static IEnumerable<byte> Decrypt(IEnumerable<byte> data, string password, X509Certificate2? privateKey = null)
    {
        return DecryptInternal(data, HelperFunctions.ToSecureString(password), privateKey);
    }

    /// <summary>
    /// Decrypts an <see cref="IEnumerable{T}"/>; 
    /// </summary>
    /// <param name="data">The encrypted data to decrypt.</param>
    /// <param name="password">The password used for decryption. Must be the same as the encryption password.</param>
    /// <param name="privateKey">Optional private key for decrypting the salt. Required if the data was encrypted 
    /// with a corresponding public key.</param>
    /// <returns>The decrypted data as a byte array.</returns>
    public static IEnumerable<byte> Decrypt(IEnumerable<byte> data, SecureString password, X509Certificate2? privateKey = null)
    {
        return DecryptInternal(data, password, privateKey);
    }

    // Internal method for decryption
    private static IEnumerable<byte> DecryptInternal(IEnumerable<byte> data, SecureString password, X509Certificate2? privateKey)
    {
        using MemoryStream memoryStream = new MemoryStream(data.ToArray());
        using MemoryStream decryptedStream = new MemoryStream();
        using (DecryptingStream decryptStream = new DecryptingStream(memoryStream, password, privateKey))
        {
            decryptStream.CopyTo(decryptedStream);
        }
        return decryptedStream.ToArray().AsEnumerable();
    }
}