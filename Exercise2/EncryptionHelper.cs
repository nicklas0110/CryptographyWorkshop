using System;
using System.Security.Cryptography;
using System.Text;

namespace crypto
{
    public class EncryptionHelper
    {
        private readonly byte[] _key; // Derived key
        private readonly byte[] _salt; // Salt used in PBKDF2

        public EncryptionHelper(string password)
        {
            // Generate a random salt for the client
            _salt = new byte[16]; // 128-bit salt
            RandomNumberGenerator.Fill(_salt);

            // Derive the key using PBKDF2
            using (var pbkdf2 = new Rfc2898DeriveBytes(password, _salt, 100_000, HashAlgorithmName.SHA256))
            {
                _key = pbkdf2.GetBytes(32); // 32 bytes = 256-bit key for AES
            }
        }

        // Encrypt the message using AES-GCM
        public (byte[] cipherText, byte[] iv, byte[] tag, byte[] salt) Encrypt(string plainText)
        {
            byte[] iv = new byte[12]; // 12 bytes is recommended for GCM IV
            RandomNumberGenerator.Fill(iv); // Generate a secure random IV

            byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
            byte[] cipherBytes = new byte[plainBytes.Length];
            byte[] tag = new byte[16]; // 128-bit authentication tag for GCM

            using (var aesGcm = new AesGcm(_key))
            {
                aesGcm.Encrypt(iv, plainBytes, cipherBytes, tag);
            }

            return (cipherBytes, iv, tag, _salt); // Return the ciphertext, IV, tag, and salt
        }

        // Decrypt the message using AES-GCM
        public string Decrypt(byte[] cipherText, byte[] iv, byte[] tag, byte[] salt, string password)
        {
            // Derive the key again using the provided salt and password
            byte[] derivedKey;
            using (var pbkdf2 = new Rfc2898DeriveBytes(password, salt, 100_000, HashAlgorithmName.SHA256))
            {
                derivedKey = pbkdf2.GetBytes(32); // 256-bit key
            }

            byte[] plainBytes = new byte[cipherText.Length];

            using (var aesGcm = new AesGcm(derivedKey))
            {
                aesGcm.Decrypt(iv, cipherText, tag, plainBytes);
            }

            return Encoding.UTF8.GetString(plainBytes);
        }
    }
}
