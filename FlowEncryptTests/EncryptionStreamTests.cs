using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace FlowEncrypt.Tests;

public class EncryptionStreamTests
{
    [Fact]
    public void TestEncryptionDecryption()
    {
        string originalText = "Hello, World!";
        string password = "StrongPassword";
        byte[] originalData = Encoding.UTF8.GetBytes(originalText);

        // Encrypt data
        using MemoryStream memoryStream = new ();
        using (EncryptingStream encryptStream = new (memoryStream, password, publicKey: null))
        {
            encryptStream.Write(originalData, 0, originalData.Length);
        }

        // Reset memory stream position
        memoryStream.Position = 0;

        // Decrypt data
        string decryptedText;
        using (DecryptingStream decryptStream = new (memoryStream, password))
        {
            using StreamReader sr = new (decryptStream);
            decryptedText = sr.ReadToEnd();
        }

        Assert.Equal(originalText, decryptedText);
    }

    [Fact]
    public void TestEncryptionDecryptionWithPublicKey()
    {
        string originalText = "Hello, World!";
        string password = "StrongPassword";
        byte[] originalData = Encoding.UTF8.GetBytes(originalText);

        // Load or create public and private keys
        (X509Certificate2 PublicKey, X509Certificate2 PrivateKey) keys = HelperFunctions.GenerateKeys();

        // Encrypt data
        using MemoryStream memoryStream = new ();
        using (EncryptingStream encryptStream = new (memoryStream, password, keys.PublicKey))
        {
            encryptStream.Write(originalData, 0, originalData.Length);
        }

        // Reset memory stream position
        memoryStream.Position = 0;

        // Decrypt data
        string decryptedText;
        using (DecryptingStream decryptStream = new (memoryStream, password, keys.PrivateKey))
        {
            using StreamReader sr = new (decryptStream);
            decryptedText = sr.ReadToEnd();
        }

        Assert.Equal(originalText, decryptedText);
    }
    [Fact]
    public void TestEncryptionDecryptionWithPublicKeyWrongPrivateKey()
    {
        string originalText = "Hello, World!";
        string password = "StrongPassword";
        byte[] originalData = Encoding.UTF8.GetBytes(originalText);

        // Load or create public and private keys
        (X509Certificate2 PublicKey, X509Certificate2 PrivateKey) keys = HelperFunctions.GenerateKeys();
        (X509Certificate2 PublicKey, X509Certificate2 PrivateKey) keys2 = HelperFunctions.GenerateKeys();

        // Encrypt data
        using MemoryStream memoryStream = new();
        using (EncryptingStream encryptStream = new(memoryStream, password, keys.PublicKey))
        {
            encryptStream.Write(originalData, 0, originalData.Length);
        }

        // Reset memory stream position
        memoryStream.Position = 0;

        // Attempt to decrypt data with the wrong private key
        Exception ex = Record.Exception(() =>
        {
            using DecryptingStream decryptStream = new(memoryStream, password, keys2.PrivateKey);
            using StreamReader sr = new(decryptStream);
            sr.ReadToEnd();
        });

        Assert.NotNull(ex);
        Assert.IsAssignableFrom<CryptographicException>(ex); // Check if the exception is a CryptographicException or a subclass thereof
    }


    [Fact]
    public void TestEncryptionDecryptionWithPublicKeyNoPrivateKey()
    {
        string originalText = "Hello, World!";
        string password = "StrongPassword";
        byte[] originalData = Encoding.UTF8.GetBytes(originalText);

        // Load or create public and private keys
        (X509Certificate2 PublicKey, X509Certificate2 PrivateKey) keys = HelperFunctions.GenerateKeys();

        // Encrypt data
        using MemoryStream memoryStream = new();
        using (EncryptingStream encryptStream = new(memoryStream, password, keys.PublicKey))
        {
            encryptStream.Write(originalData, 0, originalData.Length);
        }

        // Reset memory stream position
        memoryStream.Position = 0;

        // Flag to check if decryption succeeds (should remain false)
        bool decryptionSucceeded = false;

        try
        {
            using DecryptingStream decryptStream = new(memoryStream, password); // No private key provided
            using StreamReader sr = new(decryptStream);
            sr.ReadToEnd();
            decryptionSucceeded = true; // If this line is reached, decryption succeeded unexpectedly
        }
        catch
        {
            // Expected an exception, catch it and do nothing
        }

        Assert.False(decryptionSucceeded, "Decryption should have failed, but it succeeded.");
    }

}