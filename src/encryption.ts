import { createCipheriv, createDecipheriv, createHash, randomBytes } from "crypto";
import { EncryptionInput } from "./types";



export function encrypt(
    {
        plainText,
        password
    }: EncryptionInput) :string {
    const iv = randomBytes(16); // AES-256-GCM uses 12-16 byte IV
    const hash = createHash('sha512');
    const dataKey = hash.update(password, 'utf-8');
    const genHash = dataKey.digest('hex');
    const key = genHash.substring(0,32);
    const cipher = createCipheriv('aes-256-gcm', Buffer.from(key), iv);
    let encrypted = cipher.update(plainText, 'utf-8', 'base64');
    encrypted += cipher.final('base64');
    const authTag = cipher.getAuthTag();
    return encrypted + ":" + Buffer.from(iv).toString('base64') + ":" + authTag.toString('base64');
}