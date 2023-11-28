using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace FlowEncrypt
{
    internal class Encryption
    {
        
        /// <summary>
        /// encrypts a stream with AES and split salt
        /// </summary>
        /// <param name="inputStream">the data stream to encrypt</param>
        /// <param name="outputStream">the encrypted output stream</param>
        /// <param name="password">the password used for encryption</param>
        public static void EncryptStream(Stream inputStream, Stream outputStream, string password)
        {
            // Generate a new random salt
            byte[] salt = new byte[16];
            using (var rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(salt);
            }

            // Split the salt into two halves
            byte[] firstHalfOfSalt = salt.Take(8).ToArray();
            byte[] secondHalfOfSalt = salt.Skip(8).ToArray();

            // Generate key and IV from the password and full salt
            var (key, iv) = GenerateKeyAndIVFromPassword(password, salt);

            // Write the first half of the salt at the beginning of the output stream
            outputStream.Write(firstHalfOfSalt, 0, firstHalfOfSalt.Length);

            // Encrypt the content
            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;

                using (CryptoStream cs = new CryptoStream(outputStream, aes.CreateEncryptor(), CryptoStreamMode.Write, leaveOpen: true))
                {
                    inputStream.CopyTo(cs);
                    // Ensure all data is written to the output stream
                    cs.FlushFinalBlock();
                }
            }

            // Write the second half of the salt at the end of the output stream
            outputStream.Write(secondHalfOfSalt, 0, secondHalfOfSalt.Length);
        }
        /// <summary>
        /// decrypts an aer stream with split salt
        /// </summary>
        /// <param name="inputStream">the encrypted input data</param>
        /// <param name="password">the password which was used for encryption</param>
        /// <returns>decrypted output stream</returns>
        public static Stream DecryptStream(Stream inputStream, string password)
        {
            // Read the first half of the salt from the start of the stream
            byte[] firstHalfOfSalt = new byte[8];
            inputStream.Read(firstHalfOfSalt, 0, firstHalfOfSalt.Length);

            // Move to the position of the second half of the salt
            inputStream.Position = inputStream.Length - 8;

            // Read the second half of the salt
            byte[] secondHalfOfSalt = new byte[8];
            inputStream.Read(secondHalfOfSalt, 0, secondHalfOfSalt.Length);

            // Combine the two halves to get the full salt
            byte[] fullSalt = firstHalfOfSalt.Concat(secondHalfOfSalt).ToArray();

            // Generate key and IV from the password and full salt
            var (key, iv) = GenerateKeyAndIVFromPassword(password, fullSalt);

            // Exclude the second half of the salt from the encrypted data
            inputStream.SetLength(inputStream.Length - 8);

            // Reset the position of the stream to just after the first half of the salt
            inputStream.Position = 8;

            MemoryStream decryptedStream = new MemoryStream();

            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;

                using (CryptoStream cs = new CryptoStream(inputStream, aes.CreateDecryptor(), CryptoStreamMode.Read, leaveOpen: true))
                {
                    cs.CopyTo(decryptedStream);
                }
            }

            // Reset the position of the decrypted stream to the beginning
            decryptedStream.Position = 0;
            return decryptedStream;
        }
    }
}
