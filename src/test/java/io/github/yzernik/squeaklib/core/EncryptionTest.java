package io.github.yzernik.squeaklib.core;

import org.junit.Test;

import javax.crypto.Cipher;

import static org.bitcoinj.core.Utils.HEX;
import static org.junit.Assert.assertEquals;

public class EncryptionTest {

    @Test
    public void testBlockSize() throws Exception {
        Cipher cipher = Encryption.createDataCipher();

        assertEquals(cipher.getBlockSize(), 16);
    }

    @Test
    public void testEncryptDecrypt() throws Exception {
        byte[] dataKey = Encryption.generateDataKey();
        byte[] iv = Encryption.generateIV();
        byte[] content = TestUtils.generateRandomContent();
        byte[] encryptedContent = Encryption.encryptContent(dataKey, iv, content);
        byte[] decryptedContent = Encryption.decryptContent(dataKey, iv, encryptedContent);

        assertEquals(HEX.encode(decryptedContent), HEX.encode(content));
    }

    @Test
    public void testSerializeDecryptionKey() throws EncryptionException {
        Encryption.EncryptionDecryptionKeyPair keyPair = Encryption.EncryptionDecryptionKeyPair.generateKeyPair();
        Encryption.DecryptionKey decryptionKey = keyPair.getDecryptionKey();
        byte[] serialized = decryptionKey.getBytes();
        Encryption.DecryptionKey deserializedDecryptionKey = Encryption.DecryptionKey.fromBytes(serialized);

        assertEquals(decryptionKey.getPrivateKey(), deserializedDecryptionKey.getPrivateKey());
    }

    @Test
    public void testSerializeEncryptionKey() throws EncryptionException {
        Encryption.EncryptionDecryptionKeyPair keyPair = Encryption.EncryptionDecryptionKeyPair.generateKeyPair();
        Encryption.EncryptionKey encryptionKey = keyPair.getEncryptionKey();
        byte[] serialized = encryptionKey.getBytes();
        Encryption.EncryptionKey deserializedEncryptionKey = Encryption.EncryptionKey.fromBytes(serialized);

        assertEquals(encryptionKey.getPublicKey(), deserializedEncryptionKey.getPublicKey());
    }

    @Test
    public void testEncryptAssymetric() throws EncryptionException {
        Encryption.EncryptionDecryptionKeyPair keyPair = Encryption.EncryptionDecryptionKeyPair.generateKeyPair();
        Encryption.EncryptionKey encryptionKey = keyPair.getEncryptionKey();
        Encryption.DecryptionKey decryptionKey = keyPair.getDecryptionKey();

        String message = "my message";
        byte[] messageBytes = message.getBytes();

        byte[] encryptedMessage = encryptionKey.encrypt(messageBytes);
        byte[] decryptedMessageBytes = decryptionKey.decrypt(encryptedMessage);
        String decyptedMessage = new String(decryptedMessageBytes);

        assertEquals(decyptedMessage, message);
    }

}
