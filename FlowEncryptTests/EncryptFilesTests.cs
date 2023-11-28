using FlowEncrypt;

namespace FlowEncryptTests;

public class EncryptFilesTests
{
    [Fact]
    public void TestFileEncryptionDecryption()
    {
        string originalText = "Hello, World!";
        string password = "StrongPassword";
        string inputFile = "test.txt";
        string encryptedFile = "test_encrypted.txt";
        string decryptedFile = "test_decrypted.txt";

        // Create a test file
        File.WriteAllText(inputFile, originalText);

        // Encrypt the file
        EncryptFiles.Encrypt(inputFile, encryptedFile, password);

        // Decrypt the file
        EncryptFiles.Decrypt(encryptedFile, decryptedFile, password);

        // Read the decrypted content
        string decryptedText = File.ReadAllText(decryptedFile);

        Assert.Equal(originalText, decryptedText);

        // Clean up
        File.Delete(inputFile);
        File.Delete(encryptedFile);
        File.Delete(decryptedFile);
    }
}