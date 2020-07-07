package io.github.yzernik.squeaklib.core;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.MGF1ParameterSpec;
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
    public static final String CIPHER_TYPE = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    public static final int RSA_KEY_LENGTH = 1024;

    private static final OAEPParameterSpec oaepParams = new OAEPParameterSpec("SHA-256",
            "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);

    public static Cipher createDataCipher() throws NoSuchPaddingException, NoSuchAlgorithmException {
        return Cipher.getInstance("AES/CBC/PKCS5PADDING");
    }

    private static SecretKeySpec getSecretKey(byte[] dataKey) {
        return new SecretKeySpec(dataKey,"AES");
    }

    public static byte[] encryptContent(byte[] dataKey, byte[] iv, byte[] content) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        assert (dataKey.length == DATA_KEY_LENGTH);
        assert (iv.length == CIPHER_BLOCK_LENGTH);

        Cipher encryptor = createDataCipher();
        encryptor.init(Cipher.ENCRYPT_MODE, getSecretKey(dataKey), new IvParameterSpec(iv));
        return encryptor.doFinal(content);
    }

    public static byte[] decryptContent(byte[] dataKey, byte[] iv, byte[] cipher) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        assert (dataKey.length == DATA_KEY_LENGTH);
        assert (iv.length == CIPHER_BLOCK_LENGTH);

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

        public byte[] getEncDataKey() {
            return null;
        }

        public static EncryptionDecryptionKeyPair generateKeyPair() throws EncryptionException {
            try {
                KeyPairGenerator keyFactory = KeyPairGenerator.getInstance(RSA_ALGORITHM);
                keyFactory.initialize(RSA_KEY_LENGTH);
                KeyPair keyPair = keyFactory.generateKeyPair();
                EncryptionKey encryptionKey = new EncryptionKey(keyPair.getPublic());
                DecryptionKey decryptionKey = new DecryptionKey(keyPair.getPrivate());
                return new EncryptionDecryptionKeyPair(encryptionKey, decryptionKey);
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
                throw new EncryptionException(e);
            }
        }

    }

    public static class DecryptionKey {

        private PrivateKey privateKey;

        public DecryptionKey(PrivateKey privateKey) {
            this.privateKey = privateKey;
        }

        public static DecryptionKey fromBytes(byte[] bytes) throws EncryptionException {
            return new DecryptionKey(DecryptionKey.deserializePrivateKey(bytes));
        }

        public byte[] getBytes() {
            return DecryptionKey.serializePrivateKey(privateKey);
        }

        public PrivateKey getPrivateKey() {
            return privateKey;
        }

        public byte[] decrypt(byte[] ciphertext) throws EncryptionException {
            try {
                Cipher cipher = Cipher.getInstance(CIPHER_TYPE);
                cipher.init(Cipher.DECRYPT_MODE, privateKey, oaepParams);
                return cipher.doFinal(ciphertext);
            } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException | InvalidAlgorithmParameterException e) {
                e.printStackTrace();
                throw new EncryptionException(e);
            }
        }

        private static PrivateKey deserializePrivateKey(byte[] bytes) throws EncryptionException {
            try {
                KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
                PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(bytes);
                return keyFactory.generatePrivate(spec);
            } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                e.printStackTrace();
                throw new EncryptionException(e);
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

        public static EncryptionKey fromBytes(byte[] bytes) throws EncryptionException {
            return new EncryptionKey(EncryptionKey.deserializePublicKey(bytes));
        }

        public byte[] getBytes() {
            return EncryptionKey.serializePublicKey(publicKey);
        }

        public PublicKey getPublicKey() {
            return publicKey;
        }

        public byte[] encrypt(byte[] message) throws EncryptionException {
            try {
                Cipher cipher = Cipher.getInstance(CIPHER_TYPE);
                cipher.init(Cipher.ENCRYPT_MODE, publicKey, oaepParams);
                return cipher.doFinal(message);
            } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException | InvalidAlgorithmParameterException e) {
                e.printStackTrace();
                throw new EncryptionException(e);
            }
        }

        private static PublicKey deserializePublicKey(byte[] bytes) throws EncryptionException {
            try {
                X509EncodedKeySpec spec = new X509EncodedKeySpec(bytes);
                KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
                return keyFactory.generatePublic(spec);
            } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                e.printStackTrace();
                throw new EncryptionException(e);
            }
        }

        private static byte[] serializePublicKey(PublicKey publicKey) {
            return publicKey.getEncoded();
        }

    }

    public static class EncryptedDecryptionKey {

        private byte[] cipherBytes;

        public EncryptedDecryptionKey(byte[] cipherBytes) {
            this.cipherBytes = cipherBytes;
        }

        public byte[] getCipherBytes() {
            return cipherBytes;
        }

        public static EncryptedDecryptionKey fromBytes(byte[] cipherBytes) {
            return new EncryptedDecryptionKey(cipherBytes);
        }

        public static EncryptedDecryptionKey fromDecryptionKey(DecryptionKey decryptionKey, byte[] preimage, byte[] iv) throws NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
            byte[] decryptionKeyBytes = decryptionKey.getBytes();
            byte[] cipherKeyBytes = encryptContent(preimage, iv, decryptionKeyBytes);
            return new EncryptedDecryptionKey(cipherKeyBytes);
        }

        public DecryptionKey getDecryptionKey(byte[] preimage, byte[] iv) throws NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, EncryptionException {
            byte[] decryptionKeyBytes = decryptContent(preimage, iv, cipherBytes);
            return DecryptionKey.fromBytes(decryptionKeyBytes);
        }


    }

}
