export type EncryptionInput = {
    plainText: string,
    password: string
}

export type DecryptionInput = {
    encryptedText: string,
    password: string
}

export type DHKeyExchangeInput = {
    password?: string; // Optional fallback password
}

export type DHKeyPair = {
    privateKey: string;
    publicKey: string;
}

export type DHSharedSecretInput = {
    privateKey: string;
    otherPublicKey: string;
    password?: string; // Optional fallback password
}

export type DHEncryptionInput = {
    plainText: string;
    sharedSecret: string;
}

export type DHDecryptionInput = {
    encryptedText: string;
    sharedSecret: string;
}
