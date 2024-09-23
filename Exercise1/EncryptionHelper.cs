using System;
using System.Security.Cryptography;
using System.Text;

namespace crypto
{
    public class EncryptionHelper
    {
        private readonly byte[] _key; // Pre-shared key

        public EncryptionHelper()
        {
            // Set up a static pre-shared key (256-bit key for AES-256)
            _key = Encoding.UTF8.GetBytes("12345678901234567890123456789012"); // 32 bytes = 256 bits
        }

        // Encrypt the message using AES-GCM
        public (byte[] cipherText, byte[] iv, byte[] tag) Encrypt(string plainText)
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

            return (cipherBytes, iv, tag); // Return the ciphertext, IV, and authentication tag
        }

        // Decrypt the message using AES-GCM
        public string Decrypt(byte[] cipherText, byte[] iv, byte[] tag)
        {
            byte[] plainBytes = new byte[cipherText.Length];

            using (var aesGcm = new AesGcm(_key))
            {
                aesGcm.Decrypt(iv, cipherText, tag, plainBytes);
            }

            return Encoding.UTF8.GetString(plainBytes);
        }
    }
}