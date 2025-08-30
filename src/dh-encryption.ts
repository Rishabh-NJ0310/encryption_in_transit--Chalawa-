import { createCipheriv, createDecipheriv, createHash, randomBytes } from "crypto";
import { DHEncryptionInput, DHDecryptionInput } from "./types";

/**
 * Encrypts data using AES-256-GCM with a Diffie-Hellman shared secret
 */
export function dhEncrypt({ plainText, sharedSecret }: DHEncryptionInput): string {
    const iv = randomBytes(16); // AES-256-GCM uses 12-16 byte IV
    
    // Derive encryption key from shared secret
    const hash = createHash('sha512');
    const dataKey = hash.update(sharedSecret, 'hex');
    const genHash = dataKey.digest('hex');
    const key = genHash.substring(0, 32);
    
    const cipher = createCipheriv('aes-256-gcm', Buffer.from(key), iv);
    let encrypted = cipher.update(plainText, 'utf-8', 'base64');
    encrypted += cipher.final('base64');
    const authTag = cipher.getAuthTag();
    console.log("Encrypted:", encrypted);
    console.log("IV:", Buffer.from(iv).toString('base64'));
    console.log("Auth Tag:", authTag.toString('base64'));
    const str = `${encrypted}+ ${Buffer.from(iv).toString('base64')}+ ${authTag.toString('base64')}`
    console.log("Full Encrypted String:", str + " length of " + str.length);
    return encrypted + ":" + Buffer.from(iv).toString('base64') + ":" + authTag.toString('base64');
    
}

/**
 * Decrypts data using AES-256-GCM with a Diffie-Hellman shared secret
 */
export function dhDecrypt({ encryptedText, sharedSecret }: DHDecryptionInput): any {
    const result = encryptedText.split(":");
    if (result.length !== 3) {
        throw new Error('Invalid encrypted text format');
    }
    
    // Derive decryption key from shared secret
    const hash = createHash('sha512');
    const dataKey = hash.update(sharedSecret, 'hex');
    const genHash = dataKey.digest('hex');
    const key = genHash.substring(0, 32);
    
    const iv = Buffer.from(result[1], 'base64');
    const authTag = Buffer.from(result[2], 'base64');
    
    const decipher = createDecipheriv('aes-256-gcm', Buffer.from(key), iv);
    decipher.setAuthTag(authTag);
    
    let decrypted = decipher.update(result[0], 'base64', 'utf-8');
    decrypted += decipher.final('utf-8');
    
    return JSON.parse(decrypted);
}



/*

    CUSTOM PADDING MIDDLEWARE


*/