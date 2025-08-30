# Chalawa - Encryption in Transit

A lightweight TypeScript/JavaScript package for applying AES-256-GCM encryption to secure data in transit, with support for Diffie-Hellman key exchange.

## ⚠️ Important Security Warning

**For basic encryption: The password must be the same on your server and client machine for encryption/decryption to work properly.**

**For Diffie-Hellman: Public keys must be exchanged securely, and both parties must use the same shared secret derivation method.**

## Features

- **AES-256-GCM Encryption**: Industry-standard encryption with built-in authentication
- **Diffie-Hellman Key Exchange**: Secure key agreement without transmitting secret keys
- **Secure Key Derivation**: Uses SHA-512 for password-based key generation
- **Hybrid Security**: Combine DH key exchange with password enhancement
- **TypeScript Support**: Full type definitions included
- **Zero Dependencies**: Uses Node.js built-in crypto module
- **Simple API**: Easy-to-use functions for all encryption scenarios

## Installation

```bash
npm install chalawa
```

## Usage

### Method 1: Basic Password-Based Encryption

```typescript
import { encrypt, decrypt } from 'chalawa';

const password = 'your-secret-password';
const data = { message: 'Hello, secure world!', userId: 123 };

// Encrypt data
const encrypted = encrypt({
    plainText: JSON.stringify(data),
    password: password
});

// Decrypt data
const decrypted = decrypt({
    encryptedText: encrypted,
    password: password
});
```

### Method 2: Diffie-Hellman Key Exchange (Recommended)

```typescript
import { 
    generateDHKeyPair, 
    computeSharedSecret, 
    dhEncrypt, 
    dhDecrypt 
} from 'chalawa';

// Step 1: Both parties generate key pairs
const clientKeyPair = generateDHKeyPair();
const serverKeyPair = generateDHKeyPair();

// Step 2: Exchange public keys (send over network)
// Client sends clientKeyPair.publicKey to server
// Server sends serverKeyPair.publicKey to client

// Step 3: Both compute the same shared secret
const clientSharedSecret = computeSharedSecret({
    privateKey: clientKeyPair.privateKey,
    otherPublicKey: serverKeyPair.publicKey
});

const serverSharedSecret = computeSharedSecret({
    privateKey: serverKeyPair.privateKey,
    otherPublicKey: clientKeyPair.publicKey
});

// clientSharedSecret === serverSharedSecret (both parties have same secret!)

// Step 4: Use shared secret for encryption
const data = { userId: 123, sensitiveData: 'confidential' };

const encrypted = dhEncrypt({
    plainText: JSON.stringify(data),
    sharedSecret: clientSharedSecret
});

const decrypted = dhDecrypt({
    encryptedText: encrypted,
    sharedSecret: serverSharedSecret
});
```

### Method 3: Enhanced Security (DH + Password)

```typescript
import { 
    generateDHKeyPair, 
    computeSharedSecret, 
    dhEncrypt, 
    dhDecrypt 
} from 'chalawa';

const enhancedPassword = 'additional-security-layer';

// Generate key pairs (optionally with password enhancement)
const clientKeyPair = generateDHKeyPair({ password: enhancedPassword });
const serverKeyPair = generateDHKeyPair({ password: enhancedPassword });

// Compute shared secret with password mixing for extra security
const sharedSecret = computeSharedSecret({
    privateKey: clientKeyPair.privateKey,
    otherPublicKey: serverKeyPair.publicKey,
    password: enhancedPassword  // Additional security layer
});

// Encrypt/decrypt as usual
const encrypted = dhEncrypt({
    plainText: JSON.stringify({ secret: 'double-protected data' }),
    sharedSecret: sharedSecret
});
```

## API Reference

### Basic Encryption Functions

#### `encrypt(options: EncryptionInput): string`
- **Parameters**: `plainText` (string), `password` (string)
- **Returns**: Encrypted string with IV and auth tag

#### `decrypt(options: DecryptionInput): any`
- **Parameters**: `encryptedText` (string), `password` (string)  
- **Returns**: Decrypted and parsed data

### Diffie-Hellman Functions

#### `generateDHKeyPair(options?: DHKeyExchangeInput): DHKeyPair`
- **Parameters**: `password` (optional string for enhanced security)
- **Returns**: Object with `privateKey` and `publicKey` as hex strings

#### `computeSharedSecret(options: DHSharedSecretInput): string`
- **Parameters**: `privateKey` (string), `otherPublicKey` (string), `password` (optional)
- **Returns**: Shared secret as hex string

#### `dhEncrypt(options: DHEncryptionInput): string`
- **Parameters**: `plainText` (string), `sharedSecret` (string)
- **Returns**: Encrypted string

#### `dhDecrypt(options: DHDecryptionInput): any`
- **Parameters**: `encryptedText` (string), `sharedSecret` (string)
- **Returns**: Decrypted and parsed data

#### `validatePublicKey(publicKey: string): boolean`
- **Parameters**: `publicKey` (hex string)
- **Returns**: True if public key format is valid

## Complete Client-Server Example

### Client Side
```typescript
import { generateDHKeyPair, computeSharedSecret, dhEncrypt } from 'chalawa';

// 1. Generate client key pair
const clientKeys = generateDHKeyPair();

// 2. Send public key to server, receive server's public key
const serverPublicKey = await sendPublicKeyToServer(clientKeys.publicKey);

// 3. Compute shared secret
const sharedSecret = computeSharedSecret({
    privateKey: clientKeys.privateKey,
    otherPublicKey: serverPublicKey
});

// 4. Encrypt sensitive data
const userData = { userId: 123, creditCard: '4532-****-****-9012' };
const encryptedData = dhEncrypt({
    plainText: JSON.stringify(userData),
    sharedSecret: sharedSecret
});

// 5. Send encrypted data
await sendEncryptedData(encryptedData);
```

### Server Side
```typescript
import { generateDHKeyPair, computeSharedSecret, dhDecrypt } from 'chalawa';

// 1. Generate server key pair
const serverKeys = generateDHKeyPair();

// 2. Receive client's public key, send server's public key
app.post('/key-exchange', (req, res) => {
    const clientPublicKey = req.body.publicKey;
    
    // Compute shared secret
    const sharedSecret = computeSharedSecret({
        privateKey: serverKeys.privateKey,
        otherPublicKey: clientPublicKey
    });
    
    // Store shared secret for this session
    storeSharedSecret(req.sessionId, sharedSecret);
    
    res.json({ publicKey: serverKeys.publicKey });
});

// 3. Decrypt received data
app.post('/secure-data', (req, res) => {
    const sharedSecret = getSharedSecret(req.sessionId);
    
    const decryptedData = dhDecrypt({
        encryptedText: req.body.encryptedData,
        sharedSecret: sharedSecret
    });
    
    // Process decrypted data safely
    console.log('Received secure data:', decryptedData);
});
```

## Security Benefits of Diffie-Hellman

1. **Perfect Forward Secrecy**: Each session uses a unique key
2. **No Key Transmission**: Secret keys never travel over the network
3. **Man-in-the-Middle Protection**: When combined with certificate validation
4. **Scalability**: No need to pre-share passwords between all parties

## Security Considerations

1. **Public Key Validation**: Always validate received public keys
2. **Secure Channels**: Use HTTPS for public key exchange
3. **Key Rotation**: Generate new key pairs regularly
4. **Password Enhancement**: Use additional passwords for extra security layers
5. **Certificate Pinning**: Validate server identity during key exchange

## Migration Guide

### From Password-Only to Diffie-Hellman
```typescript
// Old way (still supported)
const encrypted = encrypt({ plainText: data, password: 'shared-secret' });

// New way (recommended)
const keyPair = generateDHKeyPair();
// ... exchange public keys ...
const sharedSecret = computeSharedSecret({ ... });
const encrypted = dhEncrypt({ plainText: data, sharedSecret });
```

## Error Handling

```typescript
try {
    const keyPair = generateDHKeyPair();
    const sharedSecret = computeSharedSecret({
        privateKey: keyPair.privateKey,
        otherPublicKey: receivedPublicKey
    });
    const decrypted = dhDecrypt({ encryptedText, sharedSecret });
} catch (error) {
    console.error('Cryptographic operation failed:', error.message);
}
```

## Examples

See the `examples/` directory for complete working examples:
- `dh-example.ts` - Complete Diffie-Hellman demonstration

## License

MIT

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Support

For issues and questions, please visit: [GitHub Issues](https://github.com/Rishabh-NJ0310/Chalawa/issues)