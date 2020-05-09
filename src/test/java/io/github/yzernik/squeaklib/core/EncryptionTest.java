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

}
