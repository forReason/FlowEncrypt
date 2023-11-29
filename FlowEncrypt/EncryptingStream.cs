using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;


namespace FlowEncrypt
{
    /// <summary>
    /// Provides a stream that encrypts data using AES with a split salt.
    /// </summary>
    public class EncryptingStream : Stream
    {
        private readonly CryptoStream _cryptoStream;
        private readonly Aes _aes;
        /// <summary>
        /// Initializes a new instance of the <see cref="EncryptingStream"/> class.
        /// </summary>
        /// <param name="baseStream">The stream where the encrypted data will be written.</param>
        /// <param name="password">The password used for encryption.</param>
        /// <param name="publicKey">Optionally provide a public key for encryption<br/>
        /// This facilitates asymmetric encryption,
        /// where data encrypted with a public key can only be decrypted with the corresponding private </param>
        public EncryptingStream(Stream baseStream, string password, X509Certificate2? publicKey = null)
            : this(baseStream, HelperFunctions.ToSecureString(password), publicKey)
        {
        }
        /// <summary>
        /// Initializes a new instance of the <see cref="EncryptingStream"/> class.
        /// </summary>
        /// <param name="baseStream">The stream where the encrypted data will be written.</param>
        /// <param name="password">The password used for encryption.</param>
        /// <param name="publicKey">Optionally provide a public key for encryption<br/>
        /// This facilitates asymmetric encryption,
        /// where data encrypted with a public key can only be decrypted with the corresponding private </param>
        public EncryptingStream(Stream baseStream, SecureString password, X509Certificate2? publicKey = null)
        {
            Stream baseStream1 = baseStream ?? throw new ArgumentNullException(nameof(baseStream));
            _aes = Aes.Create();
            _aes.KeySize = 256; // Set KeySize

            // Generate a new random salt
            byte[] salt = RandomNumberGenerator.GetBytes(16);

            if (publicKey != null)
            {
                // Encrypt the salt with the public key if provided
                using RSA? rsa = publicKey.GetRSAPublicKey();
                if (rsa == null)
                    throw new Exception("Could not identify a valid rsa public key in the keyfile");
                byte[] encryptedSalt = rsa.Encrypt(salt, RSAEncryptionPadding.OaepSHA256);

                // Write the length of the encrypted salt followed by the encrypted salt itself
                byte[] encryptedSaltLength = BitConverter.GetBytes(encryptedSalt.Length);
                baseStream1.Write(encryptedSaltLength, 0, encryptedSaltLength.Length);
                baseStream1.Write(encryptedSalt, 0, encryptedSalt.Length);
            }
            else
            {
                // Write the salt unencrypted if no public key is provided
                baseStream1.Write(salt, 0, salt.Length);
            }

            // Generate key and IV from the password and salt
            (byte[] key, byte[] iv) = HelperFunctions.GenerateKeyAndIVFromPassword(password, salt);
            _aes.Key = key;
            _aes.IV = iv;

            // Create a CryptoStream for encryption
            _cryptoStream = new CryptoStream(baseStream1, _aes.CreateEncryptor(), CryptoStreamMode.Write, leaveOpen: true);
        }
        /// <summary>
        /// flushes the stream
        /// </summary>
        public override void Flush()
        {
            _cryptoStream.Flush();
        }

        /// <summary>
        /// disposes the stream
        /// </summary>
        /// <param name="disposing"></param>
        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                // Ensure all data is written to the base stream
                _cryptoStream.FlushFinalBlock();
                _cryptoStream.Dispose();
                _aes.Dispose();
            }
            base.Dispose(disposing);
        }

        /// <summary>
        /// writes
        /// </summary>
        /// <param name="buffer"></param>
        /// <param name="offset"></param>
        /// <param name="count"></param>
        public override void Write(byte[] buffer, int offset, int count)
        {
            _cryptoStream.Write(buffer, offset, count);
        }

        // Other necessary overrides like CanRead, CanSeek, CanWrite, Length, Position, Read, Seek, SetLength
        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }
        public override int Read(byte[] buffer, int offset, int count)
        {
            throw new NotSupportedException();
        }
        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotSupportedException();
        }
        public override void SetLength(long value)
        {
            throw new NotSupportedException();
        }
    }
}