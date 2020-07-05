package io.github.yzernik.squeaklib.core;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class Encryption {

    public static final int DATA_KEY_LENGTH = 32;
    public static final int CIPHER_BLOCK_LENGTH = 16;
    public static final int NONCE_LENGTH = 4;
    public static final int CONTENT_LENGTH = 1120;
    public static final int CIPHERTEXT_LENGTH = 1136;

    /** Algorithm used by RSA keys and ciphers. */
    public static final String RSA_ALGORITHM = "RSA";
    public static final String CIPHER_TYPE = "RSA/ECB/PKCS1Padding";
    public static final int RSA_KEY_LENGTH = 1024;


    public static Cipher createDataCipher() throws NoSuchPaddingException, NoSuchAlgorithmException {
        return Cipher.getInstance("AES/CBC/PKCS5PADDING");
    }

    private static SecretKeySpec getSecretKey(byte[] dataKey) {
        return new SecretKeySpec(dataKey,"AES");
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

    public static class EncryptionDecryptionKeyPair {

        private EncryptionKey encryptionKey;
        private DecryptionKey decryptionKey;

        public EncryptionDecryptionKeyPair(EncryptionKey encryptionKey, DecryptionKey decryptionKey) {
            this.encryptionKey = encryptionKey;
            this.decryptionKey = decryptionKey;
        }

        public EncryptionKey getEncryptionKey() {
            return encryptionKey;
        }

        public DecryptionKey getDecryptionKey() {
            return decryptionKey;
        }

        public static EncryptionDecryptionKeyPair generateKeyPair() {
            try {
                KeyPairGenerator keyFactory = KeyPairGenerator.getInstance(RSA_ALGORITHM);
                keyFactory.initialize(RSA_KEY_LENGTH);
                KeyPair keyPair = keyFactory.generateKeyPair();
                EncryptionKey encryptionKey = new EncryptionKey(keyPair.getPublic());
                DecryptionKey decryptionKey = new DecryptionKey(keyPair.getPrivate());
                return new EncryptionDecryptionKeyPair(encryptionKey, decryptionKey);
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
                return null;
            }
        }

    }

    public static class DecryptionKey {

        private PrivateKey privateKey;

        public DecryptionKey(PrivateKey privateKey) {
            this.privateKey = privateKey;
        }

        public static DecryptionKey fromBytes(byte[] bytes) {
            return new DecryptionKey(DecryptionKey.deserializePrivateKey(bytes));
        }

        public byte[] getBytes() {
            return DecryptionKey.serializePrivateKey(privateKey);
        }

        public PrivateKey getPrivateKey() {
            return privateKey;
        }

        public byte[] decrypt(byte[] ciphertext) {
            try {
                Cipher cipher = Cipher.getInstance(CIPHER_TYPE);
                cipher.init(Cipher.DECRYPT_MODE, privateKey);
                return cipher.doFinal(ciphertext);
            } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
                e.printStackTrace();
                return null;
            }
        }

        private static PrivateKey deserializePrivateKey(byte[] bytes) {
            try {
                KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
                PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(bytes);
                return keyFactory.generatePrivate(spec);
            } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                e.printStackTrace();
                return null;
            }
        }

        private static byte[] serializePrivateKey(PrivateKey privateKey) {
            byte[] encodedBytes = privateKey.getEncoded();
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(encodedBytes);
            return spec.getEncoded();
        }

    }


    public static class EncryptionKey {

        private PublicKey publicKey;

        public EncryptionKey(PublicKey publicKey) {
            this.publicKey = publicKey;
        }

        public static EncryptionKey fromBytes(byte[] bytes) {
            return new EncryptionKey(EncryptionKey.deserializePublicKey(bytes));
        }

        public byte[] getBytes() {
            return EncryptionKey.serializePublicKey(publicKey);
        }

        public PublicKey getPublicKey() {
            return publicKey;
        }

        public byte[] encrypt(byte[] message) {
            try {
                Cipher cipher = Cipher.getInstance(CIPHER_TYPE);
                cipher.init(Cipher.ENCRYPT_MODE, publicKey);
                return cipher.doFinal(message);
            } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
                e.printStackTrace();
                return null;
            }
        }

        private static PublicKey deserializePublicKey(byte[] bytes) {
            try {
                X509EncodedKeySpec spec = new X509EncodedKeySpec(bytes);
                KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
                return keyFactory.generatePublic(spec);
            } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                e.printStackTrace();
                return null;
            }
        }

        private static byte[] serializePublicKey(PublicKey publicKey) {
            return publicKey.getEncoded();
        }

    }

}
