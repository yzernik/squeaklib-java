package io.github.yzernik.squeaklib.core;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class Encryption {

    public static final int DATA_KEY_LENGTH = 32;
    public static final int CIPHER_BLOCK_LENGTH = 16;
    public static final int NONCE_LENGTH = 4;
    public static final int CONTENT_LENGTH = 1120;
    public static final int CIPHERTEXT_LENGTH = 1136;



    public static Cipher createDataCipher() throws NoSuchPaddingException, NoSuchAlgorithmException {
        return Cipher.getInstance("AES/CBC/PKCS5PADDING");
    }

    private static SecretKeySpec getSecretKey(byte[] dataKey) {
        return new SecretKeySpec(dataKey,"AES");
    }

    private static int blockSizeBits() {
        return CIPHER_BLOCK_LENGTH * 8;
    }

    public static byte[] encryptContent(byte[] dataKey, byte[] iv, byte[] content) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        assert (dataKey.length == DATA_KEY_LENGTH);
        assert (iv.length == CIPHER_BLOCK_LENGTH);
        assert (content.length == CONTENT_LENGTH);

        Cipher encryptor = createDataCipher();
        encryptor.init(Cipher.ENCRYPT_MODE, getSecretKey(dataKey), new IvParameterSpec(iv));
        return encryptor.doFinal(content);
    }

    public static byte[] decryptContent(byte[] dataKey, byte[] iv, byte[] cipher) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        assert (dataKey.length == DATA_KEY_LENGTH);
        assert (iv.length == CIPHER_BLOCK_LENGTH);
        assert (cipher.length == CIPHERTEXT_LENGTH);

        Cipher decryptor = createDataCipher();
        decryptor.init(Cipher.DECRYPT_MODE, getSecretKey(dataKey), new IvParameterSpec(iv));
        return decryptor.doFinal(cipher);
    }

    public static byte[] generateDataKey() {
        SecureRandom random = new SecureRandom();
        byte bytes[] = new byte[DATA_KEY_LENGTH];
        random.nextBytes(bytes);
        return bytes;
    }

    public static byte[] generateIV() {
        SecureRandom random = new SecureRandom();
        byte bytes[] = new byte[CIPHER_BLOCK_LENGTH];
        random.nextBytes(bytes);
        return bytes;
    }


    public static long generateNonce() {
        SecureRandom random = new SecureRandom();
        byte bytes[] = new byte[NONCE_LENGTH];
        random.nextBytes(bytes);
        return ByteBuffer.wrap(bytes).getInt();
    }

}
