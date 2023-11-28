using System.Security.Cryptography;


namespace FlowEncrypt
{
    /// <summary>
    /// Provides a stream that encrypts data using AES with a split salt.
    /// </summary>
    internal class EncryptingStream : Stream
    {
        private readonly Stream _baseStream;
        private readonly CryptoStream _cryptoStream;
        private readonly Aes _aes;
        private readonly byte[] _secondHalfOfSalt;

        /// <summary>
        /// Initializes a new instance of the <see cref="EncryptingStream"/> class.
        /// </summary>
        /// <param name="baseStream">The stream where the encrypted data will be written.</param>
        /// <param name="password">The password used for encryption.</param>
        public EncryptingStream(Stream baseStream, string password) : base()
        {
            _baseStream = baseStream;

            // Generate a new random salt
            byte[] salt = RandomNumberGenerator.GetBytes(16);

            // Split the salt into two halves
            byte[] firstHalfOfSalt = salt.Take(8).ToArray();
            _secondHalfOfSalt = salt.Skip(8).ToArray();

            // Generate key and IV from the password and full salt
            (_aes = Aes.Create()).KeySize = 256; // Set KeySize
            var (key, iv) = HelperFunctions.GenerateKeyAndIVFromPassword(password, salt);
            _aes.Key = key;
            _aes.IV = iv;

            // Write the first half of the salt at the beginning of the base stream
            _baseStream.Write(firstHalfOfSalt, 0, firstHalfOfSalt.Length);

            // Create a CryptoStream for encryption
            _cryptoStream = new CryptoStream(_baseStream, _aes.CreateEncryptor(), CryptoStreamMode.Write, leaveOpen: true);
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

                // Write the second half of the salt at the end of the base stream
                _baseStream.Write(_secondHalfOfSalt, 0, _secondHalfOfSalt.Length);
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