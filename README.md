# SecurePasswordCrypt

A secure and reusable C# library that provides password hashing, AES-GCM encryption, and password verification. Useful for scenarios where storing or using plaintext passwords (e.g., in connection strings) is a risk.

## Features

- AES-GCM encryption with authentication tag
- PBKDF2 (Rfc2898) key derivation
- SHA-256-based password hashing
- Secure password verification (constant time)
- Easy-to-integrate as a class library or NuGet package
- Fully self-contained, no external dependencies

---

## Installation

### Option 1: Add as Project Reference (only if you have access to source code)

```bash
dotnet add reference ../SecurePasswordCrypt/SecurePasswordCrypt.csproj
```

### Option 2: Use as NuGet Package

```bash
dotnet add package SecurePasswordCrypt
```

## How It Works
### AES-GCM Encryption
AES-GCM is used for encrypting plaintext securely using:
- Random 128-bit salt
- Random 96-bit nonce
- 100,000 PBKDF2 iterations for key derivation
- Authentication tag for tamper protection

The result is encoded as Base64, containing:

```csharp
[salt | nonce | tag | ciphertext]
```

### Password Hashing
Passwords are hashed using PBKDF2 (HMAC-SHA256) and stored in the format:

```csharp
[salt + derived key] as Base64
```

This can be verified later using constant-time comparison.

---

## Example Usage
### Encrypt / Decrypt a password or connection string
```csharp
string plainText = "MySecretPassword!";
string password = "SuperSecureKey123";

string encrypted = CryptoService.Encrypt(plainText, password);
string decrypted = CryptoService.Decrypt(encrypted, password);
```

### Hash a password (for storage)
```csharp
string password = "user_password";
string hashed = CryptoService.HashPassword(password);

// Save to DB
```

### Verify a user login
```csharp
bool isValid = CryptoService.VerifyPassword("user_input", storedHash);
```

## API Overview
```csharp
public static class CryptoService
{
    string Encrypt(string plaintext, string password)
    string Decrypt(string base64CipherText, string password)
    string HashPassword(string password)
    bool   VerifyPassword(string password, string storedHash)
}
```

## Use Cases
- Secure connection strings for background jobs or CI/CD
- Encrypted configuration values
- Custom authentication flows
- Secrets stored in local config (securely)

## Security Notes
- Never hard-code encryption keys or passwords
- Store secrets using secure mechanisms (e.g., environment variables, vaults)
- Always use a unique salt per password
- Don't use this library for token signing (use asymmetric keys instead)

## Author
Developed by [Alwil17](https://github.com/Alwil17) — feel free to fork, improve, and share!
