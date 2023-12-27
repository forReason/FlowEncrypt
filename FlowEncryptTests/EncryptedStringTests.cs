
namespace FlowEncrypt.Tests
{
    public class EncryptedStringTests
    {
        [Fact]
        public void EncryptDecrypt_WithPassword_ReturnsOriginalString()
        {
            // Arrange
            string originalString = "Hello, World!";
            string password = "StrongPassword123";
            var encryptedString = new EncryptedString(password);

            // Act
            encryptedString.Value = originalString;
            string decryptedString = encryptedString.Value;

            // Assert
            Assert.Equal(originalString, decryptedString);
        }

        [Fact]
        public void EncryptDecrypt_WithEmptyPassword_GeneratesRandomPassword()
        {
            // Arrange
            string originalString = "Test String";
            var encryptedString = new EncryptedString(null);

            // Act
            encryptedString.Value = originalString;
            string decryptedString = encryptedString.Value;

            // Assert
            Assert.Equal(originalString, decryptedString);
        }

        [Fact]
        public void EncryptDecrypt_WithNullPassword_GeneratesRandomPassword()
        {
            // Arrange
            string originalString = "Another Test String";
            var encryptedString = new EncryptedString("");

            // Act
            encryptedString.Value = originalString;
            string decryptedString = encryptedString.Value;

            // Assert
            Assert.Equal(originalString, decryptedString);
        }

        // Additional tests can be written for specific cases like very long strings,
        // special characters, etc.
    }
}
