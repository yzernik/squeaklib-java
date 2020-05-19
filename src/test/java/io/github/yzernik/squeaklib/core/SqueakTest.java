package io.github.yzernik.squeaklib.core;

import com.google.common.io.ByteStreams;
import org.bitcoinj.core.Context;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.Sha256Hash;
import org.bitcoinj.params.MainNetParams;
import org.bitcoinj.params.RegTestParams;
import org.bitcoinj.params.TestNet3Params;
import org.bitcoinj.params.UnitTestParams;
import org.bitcoinj.script.ScriptOpCodes;
import org.junit.Before;
import org.junit.Test;

import static org.bitcoinj.core.Utils.HEX;
import static org.bitcoinj.core.Utils.reverseBytes;
import static org.junit.Assert.assertEquals;

public class SqueakTest {
    private static final NetworkParameters TESTNET = TestNet3Params.get();
    private static final NetworkParameters UNITTEST = UnitTestParams.get();
    private static final NetworkParameters MAINNET = MainNetParams.get();
    private static final NetworkParameters REGTEST = RegTestParams.get();

    private byte[] exampleSqueakBytes;
    private Squeak exampleSqueak;
    private Squeak exampleSqueakBadSig;
    private Squeak exampleSqueakMissingDataKey;
    private Squeak exampleSqueakBadDataKey;
    private Squeak exampleSqueakBadEncContent;

    @Before
    public void setUp() throws Exception {
        new Context(MAINNET);
        // One with some of transactions in, so a good test of the merkle tree hashing.
        exampleSqueakBytes = ByteStreams.toByteArray(SqueakTest.class.getResourceAsStream("squeak_example.dat"));
        NetworkParameters networkParameters = MAINNET;

        // Set up squeak
        SqueakSerializer squeakSerializer = new SqueakSerializer(networkParameters, true);
        exampleSqueak = squeakSerializer.makeSqueak(exampleSqueakBytes);

        // Set up squeak with bad signature
        exampleSqueakBadSig = squeakSerializer.makeSqueak(exampleSqueakBytes);
        byte[] badScriptSigBytes = exampleSqueakBadSig.getScriptSig().getProgram();
        badScriptSigBytes[10] = (byte) 'x';
        SqueakScript badScriptSig = new SqueakScript(badScriptSigBytes);
        exampleSqueakBadSig.setScriptSig(badScriptSig);

        // Set up squeak with bad data key
        byte[] randomDataKey = Encryption.generateDataKey();
        exampleSqueakBadDataKey = squeakSerializer.makeSqueak(exampleSqueakBytes);
        exampleSqueakBadDataKey.setDataKey(randomDataKey);

        // Set up squeak with missing data key
        exampleSqueakMissingDataKey = squeakSerializer.makeSqueak(exampleSqueakBytes);
        exampleSqueakMissingDataKey.clearDataKey();

        // Set up squeak with bad enc content
        byte[] randomContent = TestUtils.generateRandomContent();
        exampleSqueakBadEncContent = squeakSerializer.makeSqueak(exampleSqueakBytes);
        exampleSqueakBadEncContent.setEncContent(randomContent);

    }

    @Test
    public void testHash() throws Exception {
        assertEquals("4d320a62da0b85fa749e6910ae0b4f33e384b9a1af78055d25f0e7d040bd76ef", exampleSqueak.getHashAsString());
    }

    @Test
    public void testGetVersion() throws Exception {
        assertEquals(exampleSqueak.getVersion(), 1);
    }

    @Test
    public void testGetPubKey() throws Exception {
        assertEquals(exampleSqueak.getScriptPubKey().getChunks().get(0).opcode, ScriptOpCodes.OP_DUP);
        assertEquals(exampleSqueak.getScriptPubKey().getChunks().get(1).opcode, ScriptOpCodes.OP_HASH160);
        assert(exampleSqueak.getScriptPubKey().getChunks().get(2).isPushData());
        assertEquals(exampleSqueak.getScriptPubKey().getChunks().get(3).opcode, ScriptOpCodes.OP_EQUALVERIFY);
        assertEquals(exampleSqueak.getScriptPubKey().getChunks().get(4).opcode, ScriptOpCodes.OP_CHECKSIG);
    }

    @Test
    public void testHashDataKey() throws Exception {
        assertEquals("a892b040034ca5e70da84d7e5997653004df21de39e9db946692ebe7819a8f60", exampleSqueak.getHashDataKey().toString());
    }

    @Test
    public void testIV() throws Exception {
        assertEquals("036516e4f1c0c55e1201e0a28f016ff3", HEX.encode(reverseBytes(exampleSqueak.getVchIv())));
    }

    @Test
    public void testTime() throws Exception {
        assertEquals(1588050767, exampleSqueak.getTime());
    }

    @Test
    public void testNonce() throws Exception {
        assertEquals(0x2885819d, exampleSqueak.getNonce());
    }

    @Test
    public void testVerify() throws Exception {
        exampleSqueak.verify();
    }

    @Test(expected = VerificationException.class)
    public void testVerifyBadSignature() throws Exception {
        exampleSqueakBadSig.verify();
    }

    @Test
    public void testVerifyHeaderBadSignature() throws Exception {
        exampleSqueakBadSig.verifyHeader();
    }

    @Test(expected = VerificationException.class)
    public void testVerifyBadDataKey() throws Exception {
        exampleSqueakBadDataKey.verify();
    }

    @Test
    public void testVerifyHeaderBadDataKey() throws Exception {
        exampleSqueakBadDataKey.verifyHeader();
    }

    @Test
    public void testVerifyBadDataKeySkipDecryptCheck() throws Exception {
        exampleSqueakBadDataKey.verify(true);
    }

    @Test(expected = VerificationException.class)
    public void testVerifyMissingDataKey() throws Exception {
        exampleSqueakMissingDataKey.verify();
    }

    @Test
    public void testVerifyHeaderMissingDataKey() throws Exception {
        exampleSqueakMissingDataKey.verifyHeader();
    }

    @Test
    public void testVerifyMissingDataKeySkipDecryptCheck() throws Exception {
        exampleSqueakMissingDataKey.verify(true);
    }

    @Test(expected = VerificationException.class)
    public void testVerifyBadEncContent() throws Exception {
        exampleSqueakBadEncContent.verify();
    }

    @Test
    public void testVerifyHeaderBadEncContent() throws Exception {
        exampleSqueakBadEncContent.verifyHeader();
    }

    @Test
    public void testGetDecryptedContent() throws Exception {
        byte[] decryptedContent = exampleSqueak.getDecryptedContent();
        String decryptedMessage = exampleSqueak.getDecryptedContentStr();

        assertEquals(decryptedContent.length, 1120);
        assertEquals(decryptedMessage, "Hello world!");
    }


    @Test
    public void testGetAddress() throws Exception {
        assertEquals("1LndtWRXeZKUBjRu4K28d26PVWHopFJ9Z6", exampleSqueak.getAddress().toString());
    }

    @Test
    public void testMakeSqueak() throws Exception {
        Signing.KeyPair keyPair = new Signing.BitcoinjKeyPair();
        String message = "test message 123";
        Squeak squeak = Squeak.makeSqueakFromStr(
                MAINNET,
                keyPair,
                message,
                0,
                Sha256Hash.wrap("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"),
                System.currentTimeMillis() / 1000,
                Sha256Hash.wrap("0000000000000000000000000000000000000000000000000000000000000000")
        );

        squeak.verify();
        assertEquals(squeak.getDecryptedContentStr(), "test message 123");
    }

    @Test
    public void testHeaderParse() throws Exception {
        Squeak squeakHeader = exampleSqueak.cloneAsHeader();
        SqueakSerializer squeakSerializer = new SqueakSerializer(MAINNET, true);
        Squeak reparsed = squeakSerializer.makeSqueak(squeakHeader.bitcoinSerialize());

        assertEquals(reparsed, squeakHeader);
        reparsed.verifyHeader();
    }


    @Test
    public void testSerializeDeserialize() throws Exception {
        SqueakSerializer squeakSerializer = new SqueakSerializer(MAINNET, true);
        Squeak reparsed = squeakSerializer.makeSqueak(exampleSqueak.bitcoinSerialize());

        assertEquals(reparsed, exampleSqueak);
    }

    @Test
    public void testConstructor() throws Exception {
        Squeak otherSqueak = new Squeak(
                MainNetParams.get(),
                exampleSqueak.getHashEncContent(),
                exampleSqueak.getHashReplySqk(),
                exampleSqueak.getHashBlock(),
                exampleSqueak.getBlockHeight(),
                exampleSqueak.getScriptPubKey().getProgram(),
                exampleSqueak.getHashDataKey(),
                exampleSqueak.getVchIv(),
                exampleSqueak.getTime(),
                exampleSqueak.getNonce(),
                exampleSqueak.getEncContent(),
                exampleSqueak.getDataKey()
        );

        assertEquals(otherSqueak, exampleSqueak);
    }

}