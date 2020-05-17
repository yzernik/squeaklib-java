package io.github.yzernik.squeaklib.core;

import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.Sha256Hash;
import org.bitcoinj.params.MainNetParams;
import org.junit.Before;
import org.junit.Test;

import java.security.SecureRandom;

public class SigningTest {

    private ECKey ecKey;
    private Signing.KeyPair keyPair;

    @Before
    public void setUp() throws Exception {
        ecKey = new ECKey();
        keyPair = new Signing.BitcoinjKeyPair(ecKey);
    }

    @Test
    public void testSignVerify() throws Exception {
        Sha256Hash hash = Sha256Hash.of(generateRandomData());

        Signing.PrivateKey privateKey = keyPair.getPrivateKey();
        Signing.PublicKey publicKey = keyPair.getPublicKey();
        Signing.Signature signature = privateKey.sign(hash.getBytes());

        assert publicKey.verify(hash.getBytes(), signature);
    }

    @Test
    public void testSignVerifyBadSignature() throws Exception {
        Sha256Hash hash = Sha256Hash.of(generateRandomData());
        Sha256Hash hashOtherData = Sha256Hash.of(generateRandomData());

        Signing.PrivateKey privateKey = keyPair.getPrivateKey();
        Signing.PublicKey publicKey = keyPair.getPublicKey();
        Signing.Signature signature = privateKey.sign(hash.getBytes());

        assert !publicKey.verify(hashOtherData.getBytes(), signature);
    }

    @Test
    public void testGetAddress() throws Exception {
        Signing.PublicKey publicKey = keyPair.getPublicKey();
        String address = publicKey.getAddress(MainNetParams.get());

        assert (address.length() >= 26 && address.length() <= 35);
    }

    private byte[] generateRandomData() {
        SecureRandom random = new SecureRandom();
        byte bytes[] = new byte[128];
        random.nextBytes(bytes);
        return bytes;
    }

}
