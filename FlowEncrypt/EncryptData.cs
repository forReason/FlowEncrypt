using System.Security;
using System.Security.Cryptography.X509Certificates;

namespace FlowEncrypt;

public partial class EncryptData
{
    /// <summary>
    /// Encrypts an <see cref="IEnumerable{T}"/> 
    /// </summary>
    /// <param name="data">The data to encrypt.</param>
    /// <param name="password">The password used for encryption.</param>
    /// <param name="publicKey">Optional public key for encrypting the salt. If provided, 
    /// it enables asymmetric encryption of the salt.</param>
    /// <returns>The encrypted data as a byte array.</returns>
    public static IEnumerable<byte> Encrypt(IEnumerable<byte> data, string password, X509Certificate2? publicKey = null)
    {
        return EncryptInternal(data, HelperFunctions.ToSecureString(password), publicKey);
    }

    /// <summary>
    /// Encrypts an <see cref="IEnumerable{T}"/> 
    /// </summary>
    /// <param name="data">The data to encrypt.</param>
    /// <param name="password">The password used for encryption.</param>
    /// <param name="publicKey">Optional public key for encrypting the salt. If provided, 
    /// it enables asymmetric encryption of the salt.</param>
    /// <returns>The encrypted data as a byte array.</returns>
    public static IEnumerable<byte> Encrypt(IEnumerable<byte> data, SecureString password, X509Certificate2? publicKey = null)
    {
        return EncryptInternal(data, password, publicKey);
    }

    // Internal method for encryption
    private static IEnumerable<byte> EncryptInternal(IEnumerable<byte> data, SecureString password, X509Certificate2? publicKey)
    {
        using MemoryStream memoryStream = new MemoryStream(data.ToArray());
        using MemoryStream encryptedStream = new MemoryStream();
        using (EncryptingStream encryptStream = new EncryptingStream(encryptedStream, password, publicKey))
        {
            memoryStream.CopyTo(encryptStream);
        }
        return encryptedStream.ToArray().AsEnumerable();
    }
}