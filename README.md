# FlowEncrypt
<img src="https://raw.githubusercontent.com/forReason/FlowEncrypt/master/FlowEncryptLogo.png" width="200" height="200">

## Description

FlowEncrypt is a C# library providing robust encryption and decryption functionalities for files and in-memory data. Utilizing AES encryption with support for asymmetric key encryption of the salt, this library ensures secure handling of sensitive data.

## Features

- Encrypt and decrypt data streams, files and byte arrays (IEnumerable).
- Support for RSA public/private key pair for salt encryption in AES.
- Simple and intuitive API.
- Secure and efficient implementation.

## Getting Started

### Prerequisites

- .NET 8.0 or later.

### Installation

Clone the repository to your local machine:

```bash
git clone https://github.com/forReason/FlowEncrypt.git
```

### Usage

#### File Encryption and Decryption

```csharp
string inputFile = "path/to/input.txt";
string encryptedFile = "path/to/encrypted.txt";
string decryptedFile = "path/to/decrypted.txt";
string password = "yourStrongPassword";

// Encrypting a file
EncryptFiles.Encrypt(inputFile, eoutputFile, password);

// Decrypting a file
EncryptFiles.Decrypt(inputFile, outputFile, password);
```

#### In-Memory Data Encryption and Decryption

```csharp
string originalText = "Hello, World!";
IEnumerable<byte> data = Encoding.UTF8.GetBytes(originalText);

// Encrypting data
IEnumerable<byte> encryptedData = EncryptData.Encrypt(data, password);

// Decrypting data
IEnumerable<byte> decryptedData = EncryptData.Decrypt(encryptedData, password);
```

#### Simple String Encryption and decryption
You can choose to encrypt / decrypt strings with a password or you can create an encrypted string variable which automatically handles encryption/decryption whenever you access this variable
```csharp
// encrypting a string
IEnumerable<byte> encryptedData = EncryptedString.EncryptString("Mystring", "Mypassword");

// decrypting a string
string result = EncryptedString.DecryptString(encryptedData, "Mypassword");
```

```csharp
// encrypting a string in memory
var encryptedString = new EncryptedString("Optionalpassword");
encryptedString.Value = "Store this encrypted in memory";
string decryptedResult = encryptedString.Value;
```
Please note that EncryptedString uses a randomly generated password when you do not provide a password. This is the recommended option for storing strings in memory

### Usage with streams
##### Basic Encryption
```csharp
using MemoryStream outputStream = new MemoryStream(dataToEncrypt);
using (EncryptingStream encryptStream = new (outputStream, password, publicKey: null))
{
    encryptStream.Write(originalData, 0, originalData.Length);
}
```

##### Basic Decryption

```csharp
using MemoryStream inputStream = new MemoryStream(encryptedData);
using DecryptingStream decryptStream = new DecryptingStream(inputStream, password);

using StreamReader reader = new StreamReader(decryptStream);
string decryptedText = reader.ReadToEnd();
```

##### Encryption with Public Key

If the data was encrypted using a public key:

```csharp
(X509Certificate2 PublicKey, X509Certificate2 PrivateKey) keys = HelperFunctions.GenerateKeys();

using MemoryStream outputStream = new ();
using (EncryptingStream encryptStream = new (outputStream, password, keys.PublicKey))
{
    encryptStream.Write(originalData, 0, originalData.Length);
}
```

##### Decryption with Private Key

If the data was encrypted using a public key:

```csharp
(X509Certificate2 PublicKey, X509Certificate2 PrivateKey) keys = HelperFunctions.GenerateKeys();

using MemoryStream inputStream = new MemoryStream(encryptedDataWithPublicKey);
using DecryptingStream decryptStream = new DecryptingStream(inputStream, password, keys.PrivateKey);

using StreamReader reader = new StreamReader(decryptStream);
string decryptedTextWithPrivateKey = reader.ReadToEnd();
```

### Notes

- Ensure that the `EncryptStream` and `DecryptStream` are properly disposed of to release all resources.
- For encryption with a public key, ensure the corresponding private key is available for decryption.
- These classes are designed to work seamlessly with streams, making them versatile for various data sources.
## Contributing

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md) for more information.

## License

This project is licensed under the [MIT License](LICENSE).
