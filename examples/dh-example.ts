import { 
    generateDHKeyPair, 
    computeSharedSecret, 
    dhEncrypt, 
    dhDecrypt,
    validatePublicKey 
} from '../src';

// Example: Diffie-Hellman Key Exchange Implementation
async function demonstrateDHKeyExchange() {
    console.log('=== Diffie-Hellman Key Exchange Demo ===\n');

    // Step 1: Client generates key pair
    console.log('1. Client generates DH key pair...');
    const clientKeyPair = generateDHKeyPair();
    console.log('Client Public Key:', clientKeyPair.publicKey.substring(0, 32) + '...');

    // Step 2: Server generates key pair
    console.log('\n2. Server generates DH key pair...');
    const serverKeyPair = generateDHKeyPair();
    console.log('Server Public Key:', serverKeyPair.publicKey.substring(0, 32) + '...');

    // Step 3: Both parties exchange public keys and compute shared secret
    console.log('\n3. Computing shared secrets...');
    
    const clientSharedSecret = computeSharedSecret({
        privateKey: clientKeyPair.privateKey,
        otherPublicKey: serverKeyPair.publicKey
    });
    
    const serverSharedSecret = computeSharedSecret({
        privateKey: serverKeyPair.privateKey,
        otherPublicKey: clientKeyPair.publicKey
    });

    // Verify both parties have the same shared secret
    const secretsMatch = clientSharedSecret === serverSharedSecret;
    console.log('Shared secrets match:', secretsMatch);
    console.log('Shared Secret:', clientSharedSecret.substring(0, 32) + '...');

    if (!secretsMatch) {
        throw new Error('Shared secrets do not match!');
    }

    // Step 4: Use shared secret for encryption/decryption
    console.log('\n4. Testing encryption with shared secret...');
    
    const sensitiveData = {
        userId: 12345,
        creditCard: '4532-1234-5678-9012',
        amount: 250.00,
        timestamp: new Date().toISOString()
    };

    // Client encrypts data
    const encryptedData = dhEncrypt({
        plainText: JSON.stringify(sensitiveData),
        sharedSecret: clientSharedSecret
    });
    
    console.log('Encrypted data:', encryptedData.substring(0, 50) + '...');

    // Server decrypts data
    const decryptedData = dhDecrypt({
        encryptedText: encryptedData,
        sharedSecret: serverSharedSecret
    });

    console.log('\n5. Decrypted data:');
    console.log(JSON.stringify(decryptedData, null, 2));

    // Step 6: Validate public key
    console.log('\n6. Public key validation:');
    console.log('Client public key valid:', validatePublicKey(clientKeyPair.publicKey));
    console.log('Server public key valid:', validatePublicKey(serverKeyPair.publicKey));
    console.log('Invalid key test:', validatePublicKey('invalid-key'));

    return {
        clientKeyPair,
        serverKeyPair,
        sharedSecret: clientSharedSecret,
        originalData: sensitiveData,
        encryptedData,
        decryptedData
    };
}

// Example: Enhanced security with password
async function demonstratePasswordEnhancedDH() {
    console.log('\n\n=== Password-Enhanced Diffie-Hellman Demo ===\n');

    const password = 'super-secret-password';

    // Generate key pairs with password enhancement
    const clientKeyPair = generateDHKeyPair({ password: password + '_client' });
    const serverKeyPair = generateDHKeyPair({ password: password + '_server' });

    // Compute shared secrets with password mixing
    const clientSharedSecret = computeSharedSecret({
        privateKey: clientKeyPair.privateKey,
        otherPublicKey: serverKeyPair.publicKey,
        password: password
    });

    const serverSharedSecret = computeSharedSecret({
        privateKey: serverKeyPair.privateKey,
        otherPublicKey: clientKeyPair.publicKey,
        password: password
    });

    console.log('Password-enhanced secrets match:', clientSharedSecret === serverSharedSecret);

    // Test encryption with enhanced security
    const data = { message: 'This uses both DH and password security!' };
    
    const encrypted = dhEncrypt({
        plainText: JSON.stringify(data),
        sharedSecret: clientSharedSecret
    });

    const decrypted = dhDecrypt({
        encryptedText: encrypted,
        sharedSecret: serverSharedSecret
    });

    console.log('Original:', data);
    console.log('Decrypted:', decrypted);
}

// Run demonstrations
if (require.main === module) {
    demonstrateDHKeyExchange()
        .then(() => demonstratePasswordEnhancedDH())
        .then(() => console.log('\n✅ All demonstrations completed successfully!'))
        .catch(error => console.error('❌ Demo failed:', error));
}
