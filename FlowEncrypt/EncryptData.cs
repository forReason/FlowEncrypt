using System.Security.Cryptography.X509Certificates;

namespace FlowEncrypt;

public class EncryptData
{
    /// <summary>
    /// Encrypts an <see cref="IEnumerable<byte>"/> 
    /// </summary>
    /// <param name="data">The data to encrypt.</param>
    /// <param name="password">The password used for encryption.</param>
    /// <param name="publicKey">Optional public key for encrypting the salt. If provided, 
    /// it enables asymmetric encryption of the salt.</param>
    /// <returns>The encrypted data as a byte array.</returns>
    public static IEnumerable<byte> Encrypt(IEnumerable<byte> data, string password, X509Certificate2? publicKey = null)
    {
        using MemoryStream memoryStream = new MemoryStream();
    
        // Write the IEnumerable<byte> to the MemoryStream
        foreach (var b in data)
        {
            memoryStream.WriteByte(b);
        }
        memoryStream.Position = 0; // Reset the position to the beginning for reading

        // Encrypt the data in the MemoryStream
        using MemoryStream encryptedStream = new MemoryStream();
        using (EncryptingStream encryptStream = new EncryptingStream(encryptedStream, password, publicKey))
        {
            memoryStream.CopyTo(encryptStream);
        }

        // Convert the encrypted data to IEnumerable<byte>
        return encryptedStream.ToArray().AsEnumerable();
    }


    /// <summary>
    /// Decrypts an <see cref="IEnumerable<byte>"/&gt; 
    /// </summary>
    /// <param name="data">The encrypted data to decrypt.</param>
    /// <param name="password">The password used for decryption. Must be the same as the encryption password.</param>
    /// <param name="privateKey">Optional private key for decrypting the salt. Required if the data was encrypted 
    /// with a corresponding public key.</param>
    /// <returns>The decrypted data as a byte array.</returns>
    public static IEnumerable<byte> Decrypt(IEnumerable<byte> data, string password, X509Certificate2? privateKey = null)
    {
        using MemoryStream memoryStream = new MemoryStream();
    
        // Write the IEnumerable<byte> to the MemoryStream
        foreach (var b in data)
        {
            memoryStream.WriteByte(b);
        }
        memoryStream.Position = 0; // Reset the position to the beginning for reading

        // Decrypt the data in the MemoryStream
        using MemoryStream decryptedStream = new MemoryStream();
        using (DecryptingStream decryptStream = new DecryptingStream(memoryStream, password, privateKey))
        {
            decryptStream.CopyTo(decryptedStream);
        }

        // Convert the decrypted data to IEnumerable<byte>
        return decryptedStream.ToArray().AsEnumerable();
    }


}