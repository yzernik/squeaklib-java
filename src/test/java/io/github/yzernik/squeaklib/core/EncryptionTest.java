package io.github.yzernik.squeaklib.core;

import org.junit.Test;

import javax.crypto.Cipher;

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
        String message = "encrypted data";
        byte[] messageBytes = message.getBytes();
        byte[] encryptedMsg = Encryption.encryptContent(dataKey, iv, messageBytes);
        byte[] decryptedMsg = Encryption.decryptContent(dataKey, iv, encryptedMsg);

        assertEquals(new String(decryptedMsg), message);
    }

}
