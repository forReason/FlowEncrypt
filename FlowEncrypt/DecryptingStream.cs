using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace FlowEncrypt
{
    /// <summary>
    /// Represents a stream that decrypts data using AES encryption with a split salt.<br/>
    /// This stream is read-only and intended for decrypting data that was previously encrypted
    /// using a corresponding encrypting stream with the same password and salt approach.
    /// </summary>
    public class DecryptingStream : Stream
    {
        private readonly CryptoStream _cryptoStream;
        /// <summary>
        /// Initializes a new instance of the <see cref="DecryptingStream"/> class.
        /// </summary>
        /// <param name="baseStream">The stream containing the encrypted data.</param>
        /// <param name="password">The password used for decryption. This password must match the password used for encryption. 
        /// The password should be strong (e.g., a combination of letters, numbers, and special characters) to ensure security.</param>
        /// <param name="privateKey">Optionally provide a private key for decryption if a public key was used to encrypt<br/>
        /// This facilitates asymmetric encryption,
        /// where data encrypted with a public key can only be decrypted with the corresponding private key.</param>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="baseStream"/> is null.</exception>
        public DecryptingStream(Stream baseStream, string password, X509Certificate2? privateKey = null)
        {
            Stream baseStream1 = baseStream ?? throw new ArgumentNullException(nameof(baseStream));

            // Read the length of the encrypted salt (if encrypted salt is used)
            byte[] salt;
            if (privateKey != null)
            {
                byte[] saltLengthBytes = new byte[4];
                _ = baseStream1.Read(saltLengthBytes, 0, 4);
                int saltLength = BitConverter.ToInt32(saltLengthBytes, 0);

                byte[] encryptedSalt = new byte[saltLength];
                _ = baseStream1.Read(encryptedSalt, 0, saltLength);

                using RSA? rsa = privateKey.GetRSAPrivateKey();
                if (rsa == null)
                    throw new Exception("private key file could not identify a valid RSA key");
                salt = rsa.Decrypt(encryptedSalt, RSAEncryptionPadding.OaepSHA256);
            }
            else
            {
                // If no private key is provided, read the salt as unencrypted
                salt = new byte[16];
                _ = baseStream1.Read(salt, 0, salt.Length);
            }

            // Generate key and IV from the password and salt
            (byte[] key, byte[] iv) = HelperFunctions.GenerateKeyAndIVFromPassword(password, salt);

            // Create a CryptoStream for decryption
            _cryptoStream = new CryptoStream(baseStream1, HelperFunctions.CreateDecryptor(key, iv), CryptoStreamMode.Read, leaveOpen: true);
        }


        // Override necessary stream methods to use _cryptoStream for read operations
        public override int Read(byte[] buffer, int offset, int count)
        {
            return _cryptoStream.Read(buffer, offset, count);
        }

        // Implement other necessary members of Stream

        // Example implementation for non-supported operations
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }
        public override void Flush() => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _cryptoStream.Dispose();
            }
            base.Dispose(disposing);
        }

    }
}
