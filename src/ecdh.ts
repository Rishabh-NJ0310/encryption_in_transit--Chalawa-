import { createECDH, createHash } from "crypto";
import { DHKeyExchangeInput, DHKeyPair, DHSharedSecretInput } from "./types";
import { dhEncrypt, dhDecrypt } from "./dh-encryption";

const CURVE = "prime256v1"; // P-256 - Compatible with Web Crypto API

/**
 * Generates an ECDH P-256 key pair
 * Use this for compatibility with React/Next.js (chalawa-web)
 */
export function generateECDHKeyPair({ password }: DHKeyExchangeInput = {}): DHKeyPair {
    const ecdh = createECDH(CURVE);
    ecdh.generateKeys();
    
    const privateKeyHex = ecdh.getPrivateKey("hex");
    const publicKeyHex = ecdh.getPublicKey("hex", "uncompressed"); // 130 hex chars, starts with "04"
    
    // Note: password mixing for the keypair is skipped here to match chalawa-node behavior,
    // actual mixing happens in computeECDHSharedSecret.
    void password;
    
    return {
        privateKey: privateKeyHex,
        publicKey: publicKeyHex
    };
}

/**
 * Computes the ECDH shared secret from private key and other party's public key
 * Use this for compatibility with React/Next.js (chalawa-web)
 */
export function computeECDHSharedSecret({ 
    privateKey, 
    otherPublicKey, 
    password 
}: DHSharedSecretInput): string {
    const ecdh = createECDH(CURVE);
    ecdh.setPrivateKey(Buffer.from(privateKey, "hex"));
    
    const sharedBytes = ecdh.computeSecret(Buffer.from(otherPublicKey, "hex"));
    
    // Hash the shared secret for consistent key length (matches chalawa-web)
    let hexSecret = createHash("sha256").update(sharedBytes).digest("hex");
    
    // Optionally mix with password for additional security
    if (password) {
        hexSecret = createHash("sha512")
            .update(Buffer.from(hexSecret, "hex"))
            .update(password)
            .digest("hex");
    }
    
    return hexSecret;
}

/**
 * Validates an ECDH public key format
 */
export function validateECDHPublicKey(publicKey: string): boolean {
    try {
        return publicKey.length === 130 && publicKey.startsWith("04");
    } catch {
        return false;
    }
}

// Export aliases for consistency when using ECDH
export const ecdhEncrypt = dhEncrypt;
export const ecdhDecrypt = dhDecrypt;
