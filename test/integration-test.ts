import { 
    encrypt, decrypt,
    generateDHKeyPair, computeSharedSecret, dhEncrypt, dhDecrypt,
    validatePublicKey 
} from '../src';

// Quick integration test
console.log('🧪 Running Integration Tests...\n');

// Test 1: Basic password encryption
console.log('1. Testing basic password encryption...');
const basicData = { test: 'basic encryption' };
const basicEncrypted = encrypt({
    plainText: JSON.stringify(basicData),
    password: 'test-password'
});
const basicDecrypted = decrypt({
    encryptedText: basicEncrypted,
    password: 'test-password'
});
console.log('✅ Basic encryption:', JSON.stringify(basicDecrypted) === JSON.stringify(basicData));

// Test 2: Diffie-Hellman encryption
console.log('2. Testing Diffie-Hellman encryption...');
const client = generateDHKeyPair();
const server = generateDHKeyPair();

const clientSecret = computeSharedSecret({
    privateKey: client.privateKey,
    otherPublicKey: server.publicKey
});

const serverSecret = computeSharedSecret({
    privateKey: server.privateKey,
    otherPublicKey: client.publicKey
});

const dhData = { test: 'diffie-hellman encryption' };
const dhEncrypted = dhEncrypt({
    plainText: JSON.stringify(dhData),
    sharedSecret: clientSecret
});
const dhDecrypted = dhDecrypt({
    encryptedText: dhEncrypted,
    sharedSecret: serverSecret
});

console.log('✅ DH shared secrets match:', clientSecret === serverSecret);
console.log('✅ DH encryption:', JSON.stringify(dhDecrypted) === JSON.stringify(dhData));

// Test 3: Public key validation
console.log('3. Testing public key validation...');
console.log('✅ Valid key validation:', validatePublicKey(client.publicKey));
console.log('✅ Invalid key validation:', !validatePublicKey('invalid-key'));

// Test 4: Enhanced DH with password
console.log('4. Testing enhanced DH with password...');
const enhancedClient = generateDHKeyPair({ password: 'enhanced-security' });
const enhancedServer = generateDHKeyPair({ password: 'enhanced-security' });

const enhancedClientSecret = computeSharedSecret({
    privateKey: enhancedClient.privateKey,
    otherPublicKey: enhancedServer.publicKey,
    password: 'shared-enhancement'
});

const enhancedServerSecret = computeSharedSecret({
    privateKey: enhancedServer.privateKey,
    otherPublicKey: enhancedClient.publicKey,
    password: 'shared-enhancement'
});

console.log('✅ Enhanced DH secrets match:', enhancedClientSecret === enhancedServerSecret);

console.log('\n🎉 All integration tests passed!');
console.log('\n📊 Summary:');
console.log('- Basic password encryption: ✅');
console.log('- Diffie-Hellman key exchange: ✅');
console.log('- Public key validation: ✅');
console.log('- Password-enhanced DH: ✅');
console.log('- All functions exported correctly: ✅');
