using System.Security;
using System.Security.Cryptography.X509Certificates;

namespace FlowEncrypt;

/// <summary>
/// Provides static methods for file encryption and decryption.
/// </summary>
public partial class EncryptFiles
{
    /// <summary>
    /// Decrypts a file.
    /// </summary>
    /// <param name="inputFilePath">Path to the encrypted input file.</param>
    /// <param name="outputFilePath">Path for the decrypted output file.</param>
    /// <param name="password">The password used for decryption. Must be the same as the encryption password.</param>
    /// <param name="privateKey">Optional private key for decrypting the salt. Required if the file was encrypted 
    /// with a corresponding public key.</param>
    public static void Decrypt(string inputFilePath, string outputFilePath, string password, X509Certificate2? privateKey = null)
    {
        DecryptInternal(inputFilePath, outputFilePath, HelperFunctions.ToSecureString(password), privateKey);
    }

    /// <summary>
    /// Decrypts a file.
    /// </summary>
    /// <param name="inputFile">FileInfo object representing the encrypted input file.</param>
    /// <param name="outputFile">FileInfo object representing the decrypted output file.</param>
    /// <param name="password">The password used for decryption. Must be the same as the encryption password.</param>
    /// <param name="privateKey">Optional private key for decrypting the salt. Required if the file was encrypted 
    /// with a corresponding public key.</param>
    public static void Decrypt(FileInfo inputFile, FileInfo outputFile, string password, X509Certificate2? privateKey = null)
    {
        DecryptInternal(inputFile.FullName, outputFile.FullName, HelperFunctions.ToSecureString(password), privateKey);
    }
    /// <summary>
    /// Decrypts a file.
    /// </summary>
    /// <param name="inputFilePath">Path to the encrypted input file.</param>
    /// <param name="outputFilePath">Path for the decrypted output file.</param>
    /// <param name="password">The password used for decryption. Must be the same as the encryption password.</param>
    /// <param name="privateKey">Optional private key for decrypting the salt. Required if the file was encrypted 
    /// with a corresponding public key.</param>
    public static void Decrypt(string inputFilePath, string outputFilePath, SecureString password, X509Certificate2? privateKey = null)
    {
        DecryptInternal(inputFilePath, outputFilePath, password, privateKey);
    }

    /// <summary>
    /// Decrypts a file.
    /// </summary>
    /// <param name="inputFile">FileInfo object representing the encrypted input file.</param>
    /// <param name="outputFile">FileInfo object representing the decrypted output file.</param>
    /// <param name="password">The password used for decryption. Must be the same as the encryption password.</param>
    /// <param name="privateKey">Optional private key for decrypting the salt. Required if the file was encrypted 
    /// with a corresponding public key.</param>
    public static void Decrypt(FileInfo inputFile, FileInfo outputFile, SecureString password, X509Certificate2? privateKey = null)
    {
        DecryptInternal(inputFile.FullName, outputFile.FullName, password, privateKey);
    }

    // Internal method for decryption
    private static void DecryptInternal(string inputFilePath, string outputFilePath, SecureString password, X509Certificate2? privateKey)
    {
        using FileStream inFile = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read);
        using FileStream outFile = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write);
        using DecryptingStream decryptStream = new DecryptingStream(inFile, password, privateKey);

        decryptStream.CopyTo(outFile);
    }
}