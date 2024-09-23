using System;
using System.Security.Cryptography;
using System.Text;

namespace crypto
{
    public class EncryptionHelper
    {
        private readonly byte[] _sharedSecret; // The shared secret derived from ECDH

        // Constructor for ECDH-based encryption
        public EncryptionHelper(byte[] sharedSecret)
        {
            _sharedSecret = sharedSecret;
        }

        // Encrypt the message using AES-GCM
        public (byte[] cipherText, byte[] iv, byte[] tag) Encrypt(string plainText)
        {
            byte[] iv = new byte[12]; // 12 bytes for GCM IV
            RandomNumberGenerator.Fill(iv); // Generate a secure random IV

            byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
            byte[] cipherBytes = new byte[plainBytes.Length];
            byte[] tag = new byte[16]; // 128-bit authentication tag for GCM

            using (var aesGcm = new AesGcm(_sharedSecret))
            {
                aesGcm.Encrypt(iv, plainBytes, cipherBytes, tag);
            }

            return (cipherBytes, iv, tag);
        }

        // Decrypt the message using AES-GCM
        public string Decrypt(byte[] cipherText, byte[] iv, byte[] tag)
        {
            byte[] plainBytes = new byte[cipherText.Length];

            using (var aesGcm = new AesGcm(_sharedSecret))
            {
                aesGcm.Decrypt(iv, cipherText, tag, plainBytes);
            }

            return Encoding.UTF8.GetString(plainBytes);
        }
    }
}