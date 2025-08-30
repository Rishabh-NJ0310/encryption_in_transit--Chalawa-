import { createDiffieHellman, createHash, DiffieHellman } from "crypto";
import { DHKeyExchangeInput, DHKeyPair, DHSharedSecretInput } from "./types";

// Pre-defined safe prime (RFC 5114 - 2048-bit MODP Group)
const PRIME_2048 = `
FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1
29024E088A67CC74020BBEA63B139B22514A08798E3404DD
EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245
E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED
EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D
C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F
83655D23DCA3AD961C62F356208552BB9ED529077096966D
670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B
E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9
DE2BCBF6955817183995497CEA956AE515D2261898FA0510
15728E5A8AACAA68FFFFFFFFFFFFFFFF`.replace(/\s/g, '');

const GENERATOR = 2;

/**
 * Generates a Diffie-Hellman key pair
 */
export function generateDHKeyPair({ password }: DHKeyExchangeInput = {}): DHKeyPair {
    const dh = createDiffieHellman(PRIME_2048, 'hex', GENERATOR);
    dh.generateKeys();
    
    let privateKey = dh.getPrivateKey();
    let publicKey = dh.getPublicKey();
    
    if (password) {
        // Enhance the keys with password-derived entropy
        const hash = createHash('sha256');
        const passwordHash = hash.update(password + Date.now().toString()).digest();
        
        // Mix password with private key for enhanced security
        const enhancedHash = createHash('sha256');
        enhancedHash.update(privateKey);
        enhancedHash.update(passwordHash);
        const enhancedPrivateKey = enhancedHash.digest();
        
        // Create new DH with enhanced private key
        const enhancedDH = createDiffieHellman(PRIME_2048, 'hex', GENERATOR);
        enhancedDH.setPrivateKey(enhancedPrivateKey);
        enhancedDH.generateKeys(); // This will compute the public key
        
        return {
            privateKey: enhancedPrivateKey.toString('hex'),
            publicKey: enhancedDH.getPublicKey().toString('hex')
        };
    }
    
    return {
        privateKey: privateKey.toString('hex'),
        publicKey: publicKey.toString('hex')
    };
}

/**
 * Computes the shared secret from private key and other party's public key
 */
export function computeSharedSecret({ 
    privateKey, 
    otherPublicKey, 
    password 
}: DHSharedSecretInput): string {
    const dh = createDiffieHellman(PRIME_2048, 'hex', GENERATOR);
    
    // Set our private key
    dh.setPrivateKey(Buffer.from(privateKey, 'hex'));
    
    // Compute shared secret
    const sharedSecret = dh.computeSecret(Buffer.from(otherPublicKey, 'hex'));
    
    // Optionally mix with password for additional security
    if (password) {
        const hash = createHash('sha512');
        hash.update(sharedSecret);
        hash.update(password);
        return hash.digest('hex');
    }
    
    // Hash the shared secret for consistent key length
    const hash = createHash('sha256');
    return hash.update(sharedSecret).digest('hex');
}

/**
 * Creates a DiffieHellman instance for manual key management
 */
export function createDHInstance(): DiffieHellman {
    const dh = createDiffieHellman(PRIME_2048, 'hex', GENERATOR);
    return dh;
}

/**
 * Validates a public key format
 */
export function validatePublicKey(publicKey: string): boolean {
    try {
        const keyBuffer = Buffer.from(publicKey, 'hex');
        // Basic validation - key should be reasonable length
        return keyBuffer.length > 100 && keyBuffer.length < 1000;
    } catch {
        return false;
    }
}
