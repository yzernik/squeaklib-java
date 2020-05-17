package io.github.yzernik.squeaklib.core;

import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.Sha256Hash;
import org.bitcoinj.core.SignatureDecodeException;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptBuilder;
import org.bitcoinj.script.ScriptOpCodes;

public class Signing {
    private static final int HASH_LENGTH = 32;


    /**
     * Create the sig script that will be used to verify the squeak.
     * @param signature
     * @param verifyingKeyBytes
     * @return
     */
    public static Script makeSigScript(ECKey.ECDSASignature signature, byte[] verifyingKeyBytes) {
        ScriptBuilder scriptBuilder = new ScriptBuilder();
        scriptBuilder.data(signature.encodeToDER());
        scriptBuilder.data(verifyingKeyBytes);
        return scriptBuilder.build();
    }


    /**
     * Create the pubkey script.
     * @param pubKeyHash
     * @return
     */
    public static Script makePubKeyScript(byte[] pubKeyHash) {
        ScriptBuilder scriptBuilder = new ScriptBuilder();
        scriptBuilder.op(ScriptOpCodes.OP_DUP);
        scriptBuilder.op(ScriptOpCodes.OP_HASH160);
        scriptBuilder.data(pubKeyHash);
        scriptBuilder.op(ScriptOpCodes.OP_EQUALVERIFY);
        scriptBuilder.op(ScriptOpCodes.OP_CHECKSIG);
        return scriptBuilder.build();
    }

    public interface KeyPair {
        public PrivateKey getPrivateKey();
        public PublicKey getPublicKey();
    }

    public interface PublicKey {
        public boolean verify(byte[] data, Signature signature) throws SigningException;
        public byte[] getPubKeyBytes();
    }

    public interface PrivateKey {
        public Signature sign(byte[] data);
    }

    public interface Signature {
        public byte[] getSignatureBytes();
    }

    public static class BitcoinjSignature implements Signature {
        private ECKey.ECDSASignature ecdsaSignature;

        public BitcoinjSignature(ECKey.ECDSASignature ecdsaSignature) {
            this.ecdsaSignature = ecdsaSignature;
        }

        public BitcoinjSignature(byte[] signatureBytes) throws SigningException {
            try {
                this.ecdsaSignature = ECKey.ECDSASignature.decodeFromDER(signatureBytes);
            } catch (SignatureDecodeException e) {
                throw new SigningException(e);
            }
        }

        @Override
        public byte[] getSignatureBytes() {
            return ecdsaSignature.encodeToDER();
        }
    }

    public static class BitcoinjPublicKey implements PublicKey {
        private byte[] pubKeyBytes;

        public BitcoinjPublicKey(byte[] pubKeyBytes) {
            this.pubKeyBytes = pubKeyBytes;
        }

        @Override
        public boolean verify(byte[] data, Signature signature) throws SigningException {
            try {
                return ECKey.verify(data, signature.getSignatureBytes(), pubKeyBytes);
            } catch (SignatureDecodeException e) {
                throw new SigningException(e);
            }
        }

        @Override
        public byte[] getPubKeyBytes() {
            return pubKeyBytes;
        }
    }

    public static class BitcoinjPrivateKey implements PrivateKey {
        private ECKey privateKey;

        public BitcoinjPrivateKey(ECKey privateKey) {
            this.privateKey = privateKey;
        }

        @Override
        public Signature sign(byte[] data) {
            if (data.length != HASH_LENGTH) {
                throw new SigningException("");
            }

            Sha256Hash dataAsHash = Sha256Hash.wrap(data);
            ECKey.ECDSASignature ecdsaSignature = privateKey.sign(dataAsHash);
            return new BitcoinjSignature(ecdsaSignature);
        }
    }

    public static class BitcoinjKeyPair implements KeyPair {
        private PrivateKey privateKey;
        private PublicKey publicKey;

        public BitcoinjKeyPair(ECKey ecKey) {
            this.privateKey = new BitcoinjPrivateKey(ecKey);
            this.publicKey = new BitcoinjPublicKey(ecKey.getPubKey());
        }

        @Override
        public PrivateKey getPrivateKey() {
            return privateKey;
        }

        @Override
        public PublicKey getPublicKey() {
            return publicKey;
        }
    }



}
