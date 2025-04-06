using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace SecurePasswordCrypt
{
    public static class CryptoService
    {
        // Configuration constants
        private const int KeySize = 32;               // 256 bits
        private const int SaltSize = 16;              // 128 bits
        private const int NonceSize = 12;             // 96 bits for AES-GCM
        private const int TagSize = 16;               // 128 bits
        private const int Iterations = 100_000;       // PBKDF2 iterations

        // Derive a key from a password and salt using PBKDF2
        private static byte[] DeriveKey(string password, byte[] salt)
        {
            using (var pbkdf2 = new Rfc2898DeriveBytes(password, salt, Iterations, HashAlgorithmName.SHA256))
            {
                return pbkdf2.GetBytes(KeySize);
            }
        }

        // Generate a cryptographically secure random byte array
        private static byte[] GenerateRandomBytes(int length)
        {
            var bytes = new byte[length];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(bytes);
            }
            return bytes;
        }

        // Encrypt plaintext using AES-GCM with a password
        public static string Encrypt(string plainText, string password)
        {
            // Generate random salt and nonce
            byte[] salt = GenerateRandomBytes(SaltSize);
            byte[] nonce = GenerateRandomBytes(NonceSize);

            // Derive key
            byte[] key = DeriveKey(password, salt);

            // Prepare buffers
            byte[] plaintextBytes = Encoding.UTF8.GetBytes(plainText);
            byte[] cipherBytes = new byte[plaintextBytes.Length];
            byte[] tag = new byte[TagSize];

            // Perform AES-GCM encryption
            using (var aesGcm = new AesGcm(key, TagSize))
            {
                aesGcm.Encrypt(nonce, plaintextBytes, cipherBytes, tag);
            }

            // Combine: salt + nonce + tag + ciphertext
            using (var ms = new MemoryStream())
            {
                ms.Write(salt, 0, salt.Length);
                ms.Write(nonce, 0, nonce.Length);
                ms.Write(tag, 0, tag.Length);
                ms.Write(cipherBytes, 0, cipherBytes.Length);
                return Convert.ToBase64String(ms.ToArray());
            }
        }

        // Decrypt ciphertext using AES-GCM with a password
        public static string Decrypt(string encryptedText, string password)
        {
            byte[] fullData = Convert.FromBase64String(encryptedText);

            // Extract components
            byte[] salt = new byte[SaltSize];
            byte[] nonce = new byte[NonceSize];
            byte[] tag = new byte[TagSize];

            Array.Copy(fullData, 0, salt, 0, SaltSize);
            Array.Copy(fullData, SaltSize, nonce, 0, NonceSize);
            Array.Copy(fullData, SaltSize + NonceSize, tag, 0, TagSize);

            int cipherStart = SaltSize + NonceSize + TagSize;
            int cipherLength = fullData.Length - cipherStart;
            byte[] cipherBytes = new byte[cipherLength];
            Array.Copy(fullData, cipherStart, cipherBytes, 0, cipherLength);

            // Derive key
            byte[] key = DeriveKey(password, salt);

            // Prepare buffer for plaintext
            byte[] plaintextBytes = new byte[cipherBytes.Length];

            // Perform AES-GCM decryption
            using (var aesGcm = new AesGcm(key, TagSize))
            {
                aesGcm.Decrypt(nonce, cipherBytes, tag, plaintextBytes);
            }

            return Encoding.UTF8.GetString(plaintextBytes);
        }

        // Hash a password using PBKDF2 (for storage)
        public static string HashPassword(string password)
        {
            byte[] salt = GenerateRandomBytes(SaltSize);
            byte[] key = DeriveKey(password, salt);

            // Store salt + key in Base64
            var combined = new byte[salt.Length + key.Length];
            Buffer.BlockCopy(salt, 0, combined, 0, salt.Length);
            Buffer.BlockCopy(key, 0, combined, salt.Length, key.Length);
            return Convert.ToBase64String(combined);
        }

        // Verify a password against a stored hash
        public static bool VerifyPassword(string password, string storedHash)
        {
            byte[] combined = Convert.FromBase64String(storedHash);
            byte[] salt = new byte[SaltSize];
            byte[] key = new byte[KeySize];

            Buffer.BlockCopy(combined, 0, salt, 0, SaltSize);
            Buffer.BlockCopy(combined, SaltSize, key, 0, KeySize);

            byte[] testKey = DeriveKey(password, salt);
            return CryptographicOperations.FixedTimeEquals(testKey, key);
        }
    }

}
