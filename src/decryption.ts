import { createCipheriv, createDecipheriv, createHash, randomBytes } from "crypto";
import { DecryptionInput } from "./types";

export function decrypt(
    {
        encryptedText,
        password
    }: DecryptionInput
) {
    let m = createHash('sha512');
    let dataKey = m.update(password, 'utf-8');
    let genHash = dataKey.digest('hex');
    let key = genHash.substring(0, 32);
    let result = encryptedText.split(":");
    if (result.length !== 3) {
        throw new Error('Invalid encrypted text format');
    }
    let iv = Buffer.from(result[1], 'base64');
    let authTag = Buffer.from(result[2], 'base64');
    let decipher = createDecipheriv('aes-256-gcm', Buffer.from(key), iv);
    decipher.setAuthTag(authTag);
    let decrypted = decipher.update(result[0], 'base64', 'utf-8');
    decrypted += decipher.final('utf-8');
    return JSON.parse(decrypted);
}
