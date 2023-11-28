using System.Security.Cryptography;

namespace FlowEncrypt
{
    internal class HelperFunctions
    {
        internal static (byte[] Key, byte[] IV) GenerateKeyAndIVFromPassword(string password, byte[] salt, int keySize = 256, int iterations = 10000)
        {
            using (var rfc2898DeriveBytes = new Rfc2898DeriveBytes(password, salt, iterations))
            {
                byte[] key = rfc2898DeriveBytes.GetBytes(keySize / 8);
                byte[] iv = rfc2898DeriveBytes.GetBytes(16); // AES block size is 16 bytes
                return (key, iv);
            }
        }
        public static ICryptoTransform CreateDecryptor(byte[] key, byte[] iv)
        {
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = key;
                aesAlg.IV = iv;
                return aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
            }
        }

    }
}
