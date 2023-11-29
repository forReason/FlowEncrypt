using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace FlowEncrypt;

/// <summary>
/// Provides utility functions for key generation and encryption/decryption.
/// </summary>
public static class HelperFunctions
{
    /// <summary>
    /// Generates RSA public and private keys and creates corresponding X509 certificates.
    /// </summary>
    /// <param name="keySize">The size of the RSA key in bits. Default is 2048.</param>
    /// <param name="password">The password to secure the private key. Default is an empty string.</param>
    /// <returns>A tuple containing the public key certificate and the private key certificate.</returns>
    public static (X509Certificate2 PublicKey, X509Certificate2 PrivateKey) GenerateKeys(int keySize = 2048, SecureString? password = null)
    {
        using RSA rsa = RSA.Create(keySize);
        // Generate public and private key pair
        CertificateRequest certificateRequest = new CertificateRequest("cn=FlowEncrypt", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        X509Certificate2 certificate = certificateRequest.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(1));

        // Separate out the public key certificate
        X509Certificate2 publicKeyCert = new X509Certificate2(certificate.Export(X509ContentType.Cert));

        // Export the private key certificate in PFX format (contains private key)
        // If password is null, use an empty SecureString
        SecureString emptyPassword = password ?? new SecureString();
        X509Certificate2 privateKeyCert = new X509Certificate2(certificate.Export(X509ContentType.Pfx), emptyPassword, X509KeyStorageFlags.Exportable);

        return (publicKeyCert, privateKeyCert);
    }

    /// <summary>
    /// Converts a regular string to a SecureString.
    /// </summary>
    /// <param name="input">The string to convert.</param>
    /// <returns>A SecureString containing the characters from the input string.</returns>
    public static SecureString ToSecureString(string input)
    {
        if (input == null)
            throw new ArgumentNullException(nameof(input));

        SecureString secure = new SecureString();
        foreach (char c in input)
        {
            secure.AppendChar(c);
        }
        secure.MakeReadOnly();
        return secure;
    }

    /// <summary>
    /// Generates a symmetric encryption key and initialization vector (IV) from a given password and salt.
    /// </summary>
    /// <param name="password">The password used for generating the key and IV.</param>
    /// <param name="salt">The salt to be used in conjunction with the password.</param>
    /// <param name="keySize">The size of the encryption key in bits. Default is 256.</param>
    /// <param name="iterations">The number of iterations for the key generation. Default is 10000.</param>
    /// <param name="hashAlgorithm">the hash algorithm to choose. default: sha-256</param>
    /// <returns>A tuple containing the generated key and IV.</returns>
    internal static (byte[] Key, byte[] IV) GenerateKeyAndIVFromPassword(
        SecureString password,
        byte[] salt,
        int keySize = 256,
        int iterations = 10000,
        HashAlgorithmName hashAlgorithm = default)
    {
        if (password == null) throw new ArgumentNullException(nameof(password));
        if (salt == null) throw new ArgumentNullException(nameof(salt));

        if (hashAlgorithm == default)
        {
            hashAlgorithm = HashAlgorithmName.SHA256; // Default to SHA-256
        }

        IntPtr passwordBSTR = IntPtr.Zero;
        byte[] passwordBytes = Array.Empty<byte>();

        try
        {
            passwordBSTR = Marshal.SecureStringToBSTR(password);
            int length = Marshal.ReadInt32(passwordBSTR, -4);
            passwordBytes = new byte[length];
            for (int i = 0; i < length; i++)
            {
                passwordBytes[i] = Marshal.ReadByte(passwordBSTR, i);
            }

            using var rfc2898DeriveBytes = new Rfc2898DeriveBytes(passwordBytes, salt, iterations, hashAlgorithm);
            byte[] key = rfc2898DeriveBytes.GetBytes(keySize / 8);
            byte[] iv = rfc2898DeriveBytes.GetBytes(16); // AES block size is 16 bytes

            return (key, iv);
        }
        finally
        {
            if (passwordBSTR != IntPtr.Zero)
            {
                Marshal.ZeroFreeBSTR(passwordBSTR);
            }

            if (passwordBytes.Length > 0)
            {
                Array.Clear(passwordBytes, 0, passwordBytes.Length);
            }
        }
    }



    /// <summary>
    /// Creates a decryptor transform for symmetric decryption using the specified key and IV.
    /// </summary>
    /// <param name="key">The symmetric key.</param>
    /// <param name="iv">The initialization vector.</param>
    /// <returns>An <see cref="ICryptoTransform"/> that can be used for cryptographic operations.</returns>
    public static ICryptoTransform CreateDecryptor(byte[] key, byte[] iv)
    {
        using Aes aesAlg = Aes.Create();
        aesAlg.Key = key;
        aesAlg.IV = iv;
        return aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
    }

}