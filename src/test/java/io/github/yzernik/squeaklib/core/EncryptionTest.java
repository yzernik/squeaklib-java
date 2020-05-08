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
        // TODO
    }

}
