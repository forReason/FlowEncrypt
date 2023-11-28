using System.Security.Cryptography.X509Certificates;

namespace FlowEncrypt;

/// <summary>
/// Provides static methods for file encryption and decryption.
/// </summary>
public class EncryptFiles
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
        using FileStream inFile = new FileStream(inputFile, FileMode.Open, FileAccess.Read);
        using FileStream outFile = new FileStream(outputFile, FileMode.Create, FileAccess.Write);
        using EncryptingStream encryptStream = new EncryptingStream(outFile, password, publicKey);

        inFile.CopyTo(encryptStream);
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
        Encrypt(inputFile.FullName, outputFile.FullName, password, publicKey);
    }

    /// <summary>
    /// Decrypts a file.
    /// </summary>
    /// <param name="inputFile">Path to the encrypted input file.</param>
    /// <param name="outputFile">Path for the decrypted output file.</param>
    /// <param name="password">The password used for decryption. Must be the same as the encryption password.</param>
    /// <param name="privateKey">Optional private key for decrypting the salt. Required if the file was encrypted 
    /// with a corresponding public key.</param>
    public static void Decrypt(string inputFile, string outputFile, string password, X509Certificate2? privateKey = null)
    {
        using FileStream inFile = new FileStream(inputFile, FileMode.Open, FileAccess.Read);
        using FileStream outFile = new FileStream(outputFile, FileMode.Create, FileAccess.Write);
        using DecryptingStream decryptStream = new DecryptingStream(inFile, password, privateKey);

        decryptStream.CopyTo(outFile);
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
        Decrypt(inputFile.FullName, outputFile.FullName, password, privateKey);
    }
}