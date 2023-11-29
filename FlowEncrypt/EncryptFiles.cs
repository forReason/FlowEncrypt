using System.Security;
using System.Security.Cryptography.X509Certificates;

namespace FlowEncrypt;

/// <summary>
/// Provides static methods for file encryption and decryption.
/// </summary>
public partial class EncryptFiles
{
    /// <summary>
    /// Encrypts a file.
    /// </summary>
    /// <param name="inputFile">Path to the input file to be encrypted.</param>
    /// <param name="outputFile">Path for the encrypted output file.</param>
    /// <param name="password">The password used for encryption.</param>
    /// <param name="publicKey">Optional public key for encrypting the salt. If provided, 
    /// it enables asymmetric encryption of the salt.</param>
    public static void Encrypt(string inputFile, string outputFile, string password, X509Certificate2? publicKey = null)
    {
        EncryptInternal(inputFile, outputFile, HelperFunctions.ToSecureString(password), publicKey);
    }

    /// <summary>
    /// Encrypts a file.
    /// </summary>
    /// <param name="inputFile">FileInfo object representing the input file to be encrypted.</param>
    /// <param name="outputFile">FileInfo object representing the encrypted output file.</param>
    /// <param name="password">The password used for encryption.</param>
    /// <param name="publicKey">Optional public key for encrypting the salt. If provided, 
    /// it enables asymmetric encryption of the salt.</param>
    public static void Encrypt(FileInfo inputFile, FileInfo outputFile, string password, X509Certificate2? publicKey = null)
    {
        EncryptInternal(inputFile.FullName, outputFile.FullName, HelperFunctions.ToSecureString(password), publicKey);
    }
    /// <summary>
    /// Encrypts a file.
    /// </summary>
    /// <param name="inputFile">Path to the input file to be encrypted.</param>
    /// <param name="outputFile">Path for the encrypted output file.</param>
    /// <param name="password">The password used for encryption.</param>
    /// <param name="publicKey">Optional public key for encrypting the salt. If provided, 
    /// it enables asymmetric encryption of the salt.</param>
    public static void Encrypt(string inputFile, string outputFile, SecureString password, X509Certificate2? publicKey = null)
    {
        EncryptInternal(inputFile, outputFile, password, publicKey);
    }

    /// <summary>
    /// Encrypts a file.
    /// </summary>
    /// <param name="inputFile">FileInfo object representing the input file to be encrypted.</param>
    /// <param name="outputFile">FileInfo object representing the encrypted output file.</param>
    /// <param name="password">The password used for encryption.</param>
    /// <param name="publicKey">Optional public key for encrypting the salt. If provided, 
    /// it enables asymmetric encryption of the salt.</param>
    public static void Encrypt(FileInfo inputFile, FileInfo outputFile, SecureString password, X509Certificate2? publicKey = null)
    {
        EncryptInternal(inputFile.FullName, outputFile.FullName, password, publicKey);
    }
    private static void EncryptInternal(string inputFile, string outputFile, SecureString password, X509Certificate2? publicKey)
    {
        using FileStream inFile = new FileStream(inputFile, FileMode.Open, FileAccess.Read);
        using FileStream outFile = new FileStream(outputFile, FileMode.Create, FileAccess.Write);
        using EncryptingStream encryptStream = new EncryptingStream(outFile, password, publicKey);

        inFile.CopyTo(encryptStream);
    }
}