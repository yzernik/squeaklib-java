package io.github.yzernik.squeaklib.core;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class Encryption {

    private static int DATA_KEY_LENGTH = 32;
    private static int CIPHER_BLOCK_LENGTH = 16;


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
        Cipher encryptor = createDataCipher();
        encryptor.init(Cipher.ENCRYPT_MODE, getSecretKey(dataKey), new IvParameterSpec(iv));
        return encryptor.doFinal(content);
    }

    public static byte[] decryptContent(byte[] dataKey, byte[] iv, byte[] cipher) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        Cipher decryptor = createDataCipher();
        decryptor.init(Cipher.DECRYPT_MODE, getSecretKey(dataKey), new IvParameterSpec(iv));
        return decryptor.doFinal(cipher);
    }

    public static byte[] generateDataKey() {
        return null;
    }

}