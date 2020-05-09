package io.github.yzernik.squeaklib.core;

import org.junit.Test;

import javax.crypto.Cipher;

import java.security.SecureRandom;

import static org.junit.Assert.assertEquals;

import static org.bitcoinj.core.Utils.HEX;

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
        byte[] content = generateRandomContent();
        byte[] encryptedContent = Encryption.encryptContent(dataKey, iv, content);
        byte[] decryptedContent = Encryption.decryptContent(dataKey, iv, encryptedContent);

        assertEquals(HEX.encode(decryptedContent), HEX.encode(content));
    }

    private byte[] generateRandomContent() {
        SecureRandom random = new SecureRandom();
        byte bytes[] = new byte[Encryption.CONTENT_LENGTH];
        random.nextBytes(bytes);
        return bytes;
    }

}
