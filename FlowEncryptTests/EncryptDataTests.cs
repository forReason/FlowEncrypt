using System.Text;
using FlowEncrypt;

namespace FlowEncrypt.Tests;

public class EncryptDataTests
{
    [Fact]
    public void TestEnumerableEncryptionDecryption()
    {
        string originalText = "Hello, World!";
        string password = "StrongPassword";
        IEnumerable<byte> originalData = Encoding.UTF8.GetBytes(originalText);

        // Encrypt the data
        IEnumerable<byte> encryptedData = EncryptData.Encrypt(originalData, password);

        // Decrypt the data
        IEnumerable<byte> decryptedData = EncryptData.Decrypt(encryptedData, password);

        // Convert decrypted data back to string
        string decryptedText = Encoding.UTF8.GetString(decryptedData.ToArray());

        Assert.Equal(originalText, decryptedText);
    }

}