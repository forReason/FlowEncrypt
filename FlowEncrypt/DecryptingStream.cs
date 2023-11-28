using System;
using System.IO;
using System.Security.Cryptography;
using System.Linq;

namespace FlowEncrypt
{
    /// <summary>
    /// Represents a stream that decrypts data using AES encryption with a split salt.<br/>
    /// This stream is read-only and intended for decrypting data that was previously encrypted
    /// using a corresponding encrypting stream with the same password and salt approach.
    /// </summary>
    internal class DecryptingStream : Stream
    {
        private readonly Stream _baseStream;
        private readonly CryptoStream _cryptoStream;
        /// <summary>
        /// Initializes a new instance of the <see cref="DecryptingStream"/> class.
        /// </summary>
        /// <param name="baseStream">The stream containing the encrypted data.</param>
        /// <param name="password">The password used for decryption. This password must match the password used for encryption. 
        /// The password should be strong (e.g., a combination of letters, numbers, and special characters) to ensure security.</param>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="baseStream"/> is null.</exception>
        public DecryptingStream(Stream baseStream, string password)
        {
            _baseStream = baseStream ?? throw new ArgumentNullException(nameof(baseStream));

            // Read the first half of the salt from the start of the stream
            byte[] firstHalfOfSalt = new byte[8];
            _baseStream.Read(firstHalfOfSalt, 0, firstHalfOfSalt.Length);

            // Move to the position of the second half of the salt
            _baseStream.Position = _baseStream.Length - 8;

            // Read the second half of the salt
            byte[] secondHalfOfSalt = new byte[8];
            _baseStream.Read(secondHalfOfSalt, 0, secondHalfOfSalt.Length);

            // Combine the two halves to get the full salt
            byte[] fullSalt = firstHalfOfSalt.Concat(secondHalfOfSalt).ToArray();

            // Generate key and IV from the password and full salt
            var (key, iv) = HelperFunctions.GenerateKeyAndIVFromPassword(password, fullSalt);

            // Exclude the second half of the salt from the encrypted data
            _baseStream.SetLength(_baseStream.Length - 8);

            // Reset the position of the stream to just after the first half of the salt
            _baseStream.Position = 8;

            // Create a CryptoStream for decryption
            _cryptoStream = new CryptoStream(_baseStream, HelperFunctions.CreateDecryptor(key, iv), CryptoStreamMode.Read, leaveOpen: true);
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
