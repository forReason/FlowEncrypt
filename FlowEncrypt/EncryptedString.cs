
using System.Security;
using System.Text;

namespace FlowEncrypt
{
    /// <summary>
    /// Represents an encrypted string, providing methods for encryption and decryption.
    /// </summary>
    public class EncryptedString
    {
        /// <summary>
        /// Initializes a new instance of the EncryptedString class.
        /// </summary>
        /// <param name="password">The password used for encryption. If null or empty, a random string is used.</param>
        public EncryptedString(string? password)
        {
            if (string.IsNullOrEmpty(password))
            {
                string randomString = HelperFunctions.GenerateRandomString(20); // Generate a random string of length 20
                Pwd = HelperFunctions.ToSecureString(randomString);
            }
            else
            {
                Pwd = HelperFunctions.ToSecureString(password);
            }
        }
        /// <summary>
        /// the password to encrypt/decrypt the instance
        /// </summary>
        private SecureString Pwd { get; set; }
        /// <summary>
        /// the public accessor to get and set the value of the string
        /// </summary>
        public string Value {  get
            {
                return DecryptString(_EncryptedString, HelperFunctions.SecureStringToString(Pwd));
            }
            set
            {
                _EncryptedString = EncryptString(value, HelperFunctions.SecureStringToString(Pwd));
            }
        }
        /// <summary>
        /// the encrypted data of the string
        /// </summary>
        private IEnumerable<byte> _EncryptedString;
        /// <summary>
        /// method for encrypting a string with a password on AES base
        /// </summary>
        /// <param name="input"></param>
        /// <param name="password"></param>
        /// <returns></returns>
        public static IEnumerable<byte> EncryptString(string input, string password)
        {
            IEnumerable<byte> originalData = Encoding.UTF8.GetBytes(input);

            // Encrypt the data
            return EncryptData.Encrypt(originalData, password);
        }
        /// <summary>
        ///  method for decrypting a string with a password on AES base
        /// </summary>
        /// <param name="encryptedData"></param>
        /// <param name="password"></param>
        /// <returns></returns>
        public static string DecryptString(IEnumerable<byte> encryptedData, string password)
        {
            IEnumerable<byte> decryptedData = EncryptData.Decrypt(encryptedData, password);

            // Convert decrypted data back to string
            return Encoding.UTF8.GetString(decryptedData.ToArray());
        }
    }
}
