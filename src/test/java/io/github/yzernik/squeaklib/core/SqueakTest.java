package io.github.yzernik.squeaklib.core;

import com.google.common.io.ByteStreams;
import org.bitcoinj.core.Context;
import org.bitcoinj.core.NetworkParameters;
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

    @Test(expected = VerificationException.class)
    public void testVerifyBadDataKey() throws Exception {
        exampleSqueakBadDataKey.verify();
    }

    @Test(expected = VerificationException.class)
    public void testVerifyMissingDataKey() throws Exception {
        exampleSqueakMissingDataKey.verify();
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

/*

    @Test
    public void testHeaderParse() throws Exception {
        Block header = block700000.cloneAsHeader();
        Block reparsed = TESTNET.getDefaultSerializer().makeBlock(header.bitcoinSerialize());
        assertEquals(reparsed, header);
    }

    @Test
    public void testBitcoinSerialization() throws Exception {
        // We have to be able to reserialize everything exactly as we found it for hashing to work. This test also
        // proves that transaction serialization works, along with all its subobjects like scripts and in/outpoints.
        //
        // NB: This tests the bitcoin serialization protocol.
        assertArrayEquals(block700000Bytes, block700000.bitcoinSerialize());
    }

    @Test
    public void testCoinbaseHeightTestnet() throws Exception {
        // Testnet block 21066 (hash 0000000004053156021d8e42459d284220a7f6e087bf78f30179c3703ca4eefa)
        // contains a coinbase transaction whose height is two bytes, which is
        // shorter than we see in most other cases.

        Block block = TESTNET.getDefaultSerializer().makeBlock(
                ByteStreams.toByteArray(getClass().getResourceAsStream("block_testnet21066.dat")));

        // Check block.
        assertEquals("0000000004053156021d8e42459d284220a7f6e087bf78f30179c3703ca4eefa", block.getHashAsString());
        block.verify(21066, EnumSet.of(Block.VerifyFlag.HEIGHT_IN_COINBASE));

        // Testnet block 32768 (hash 000000007590ba495b58338a5806c2b6f10af921a70dbd814e0da3c6957c0c03)
        // contains a coinbase transaction whose height is three bytes, but could
        // fit in two bytes. This test primarily ensures script encoding checks
        // are applied correctly.

        block = TESTNET.getDefaultSerializer().makeBlock(
                ByteStreams.toByteArray(getClass().getResourceAsStream("block_testnet32768.dat")));

        // Check block.
        assertEquals("000000007590ba495b58338a5806c2b6f10af921a70dbd814e0da3c6957c0c03", block.getHashAsString());
        block.verify(32768, EnumSet.of(Block.VerifyFlag.HEIGHT_IN_COINBASE));
    }

    @Test
    public void testReceiveCoinbaseTransaction() throws Exception {
        // Block 169482 (hash 0000000000000756935f1ee9d5987857b604046f846d3df56d024cdb5f368665)
        // contains coinbase transactions that are mining pool shares.
        // The private key MINERS_KEY is used to check transactions are received by a wallet correctly.

        // The address for this private key is 1GqtGtn4fctXuKxsVzRPSLmYWN1YioLi9y.
        final String MINING_PRIVATE_KEY = "5JDxPrBRghF1EvSBjDigywqfmAjpHPmTJxYtQTYJxJRHLLQA4mG";

        final long BLOCK_NONCE = 3973947400L;
        final Coin BALANCE_AFTER_BLOCK = Coin.valueOf(22223642);
        Block block169482 = MAINNET.getDefaultSerializer().makeBlock(ByteStreams.toByteArray(getClass().getResourceAsStream("block169482.dat")));

        // Check block.
        assertNotNull(block169482);
        block169482.verify(169482, EnumSet.noneOf(Block.VerifyFlag.class));
        assertEquals(BLOCK_NONCE, block169482.getNonce());

        StoredBlock storedBlock = new StoredBlock(block169482, BigInteger.ONE, 169482); // Nonsense work - not used in test.

        // Create a wallet contain the miner's key that receives a spend from a coinbase.
        ECKey miningKey = DumpedPrivateKey.fromBase58(MAINNET, MINING_PRIVATE_KEY).getKey();
        assertNotNull(miningKey);
        Context context = new Context(MAINNET);
        Wallet wallet = Wallet.createDeterministic(context, Script.ScriptType.P2PKH);
        wallet.importKey(miningKey);

        // Initial balance should be zero by construction.
        assertEquals(Coin.ZERO, wallet.getBalance());

        // Give the wallet the first transaction in the block - this is the coinbase tx.
        List<Transaction> transactions = block169482.getTransactions();
        assertNotNull(transactions);
        wallet.receiveFromBlock(transactions.get(0), storedBlock, NewBlockType.BEST_CHAIN, 0);

        // Coinbase transaction should have been received successfully but be unavailable to spend (too young).
        assertEquals(BALANCE_AFTER_BLOCK, wallet.getBalance(BalanceType.ESTIMATED));
        assertEquals(Coin.ZERO, wallet.getBalance(BalanceType.AVAILABLE));
    }

    @Test
    public void testBlock481815_witnessCommitmentInCoinbase() throws Exception {
        Block block481815 = MAINNET.getDefaultSerializer()
                .makeBlock(ByteStreams.toByteArray(getClass().getResourceAsStream("block481815.dat")));
        assertEquals(2097, block481815.getTransactions().size());
        assertEquals("f115afa8134171a0a686bfbe9667b60ae6fb5f6a439e0265789babc315333262",
                block481815.getMerkleRoot().toString());

        // This block has no witnesses.
        for (Transaction tx : block481815.getTransactions())
            assertFalse(tx.hasWitnesses());

        // Nevertheless, there is a witness commitment (but no witness reserved).
        Transaction coinbase = block481815.getTransactions().get(0);
        assertEquals("919a0df2253172a55bebcb9002dbe775b8511f84955b282ca6dae826fdd94f90", coinbase.getTxId().toString());
        assertEquals("919a0df2253172a55bebcb9002dbe775b8511f84955b282ca6dae826fdd94f90",
                coinbase.getWTxId().toString());
        Sha256Hash witnessCommitment = coinbase.findWitnessCommitment();
        assertEquals("3d03076733467c45b08ec503a0c5d406647b073e1914d35b5111960ed625f3b7", witnessCommitment.toString());
    }

    @Test
    public void testBlock481829_witnessTransactions() throws Exception {
        Block block481829 = MAINNET.getDefaultSerializer()
                .makeBlock(ByteStreams.toByteArray(getClass().getResourceAsStream("block481829.dat")));
        assertEquals(2020, block481829.getTransactions().size());
        assertEquals("f06f697be2cac7af7ed8cd0b0b81eaa1a39e444c6ebd3697e35ab34461b6c58d",
                block481829.getMerkleRoot().toString());
        assertEquals("0a02ddb2f86a14051294f8d98dd6959dd12bf3d016ca816c3db9b32d3e24fc2d",
                block481829.getWitnessRoot().toString());

        Transaction coinbase = block481829.getTransactions().get(0);
        assertEquals("9c1ab453283035800c43eb6461eb46682b81be110a0cb89ee923882a5fd9daa4", coinbase.getTxId().toString());
        assertEquals("2bbda73aa4e561e7f849703994cc5e563e4bcf103fb0f6fef5ae44c95c7b83a6",
                coinbase.getWTxId().toString());
        Sha256Hash witnessCommitment = coinbase.findWitnessCommitment();
        assertEquals("c3c1145d8070a57e433238e42e4c022c1e51ca2a958094af243ae1ee252ca106", witnessCommitment.toString());
        byte[] witnessReserved = coinbase.getInput(0).getWitness().getPush(0);
        assertEquals("0000000000000000000000000000000000000000000000000000000000000000", HEX.encode(witnessReserved));
        block481829.checkWitnessRoot();
    }

    @Test
    public void isBIPs() throws Exception {
        final Block genesis = MAINNET.getGenesisBlock();
        assertFalse(genesis.isBIP34());
        assertFalse(genesis.isBIP66());
        assertFalse(genesis.isBIP65());

        // 227835/00000000000001aa077d7aa84c532a4d69bdbff519609d1da0835261b7a74eb6: last version 1 block
        final Block block227835 = MAINNET.getDefaultSerializer()
                .makeBlock(ByteStreams.toByteArray(getClass().getResourceAsStream("block227835.dat")));
        assertFalse(block227835.isBIP34());
        assertFalse(block227835.isBIP66());
        assertFalse(block227835.isBIP65());

        // 227836/00000000000000d0dfd4c9d588d325dce4f32c1b31b7c0064cba7025a9b9adcc: version 2 block
        final Block block227836 = MAINNET.getDefaultSerializer()
                .makeBlock(ByteStreams.toByteArray(getClass().getResourceAsStream("block227836.dat")));
        assertTrue(block227836.isBIP34());
        assertFalse(block227836.isBIP66());
        assertFalse(block227836.isBIP65());

        // 363703/0000000000000000011b2a4cb91b63886ffe0d2263fd17ac5a9b902a219e0a14: version 3 block
        final Block block363703 = MAINNET.getDefaultSerializer()
                .makeBlock(ByteStreams.toByteArray(getClass().getResourceAsStream("block363703.dat")));
        assertTrue(block363703.isBIP34());
        assertTrue(block363703.isBIP66());
        assertFalse(block363703.isBIP65());

        // 383616/00000000000000000aab6a2b34e979b09ca185584bd1aecf204f24d150ff55e9: version 4 block
        final Block block383616 = MAINNET.getDefaultSerializer()
                .makeBlock(ByteStreams.toByteArray(getClass().getResourceAsStream("block383616.dat")));
        assertTrue(block383616.isBIP34());
        assertTrue(block383616.isBIP66());
        assertTrue(block383616.isBIP65());

        // 370661/00000000000000001416a613602d73bbe5c79170fd8f39d509896b829cf9021e: voted for BIP101
        final Block block370661 = MAINNET.getDefaultSerializer()
                .makeBlock(ByteStreams.toByteArray(getClass().getResourceAsStream("block370661.dat")));
        assertTrue(block370661.isBIP34());
        assertTrue(block370661.isBIP66());
        assertTrue(block370661.isBIP65());
    }

    @Test
    public void parseBlockWithHugeDeclaredTransactionsSize() throws Exception{
        Block block = new Block(UNITTEST, 1, Sha256Hash.ZERO_HASH, Sha256Hash.ZERO_HASH, 1, 1, 1, new ArrayList<Transaction>()) {
            @Override
            protected void bitcoinSerializeToStream(OutputStream stream) throws IOException {
                Utils.uint32ToByteStreamLE(getVersion(), stream);
                stream.write(getPrevBlockHash().getReversedBytes());
                stream.write(getMerkleRoot().getReversedBytes());
                Utils.uint32ToByteStreamLE(getTimeSeconds(), stream);
                Utils.uint32ToByteStreamLE(getDifficultyTarget(), stream);
                Utils.uint32ToByteStreamLE(getNonce(), stream);

                stream.write(new VarInt(Integer.MAX_VALUE).encode());
            }

            @Override
            public byte[] bitcoinSerialize() {
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                try {
                    bitcoinSerializeToStream(baos);
                } catch (IOException e) {
                }
                return baos.toByteArray();
            }
        };
        byte[] serializedBlock = block.bitcoinSerialize();
        try {
            UNITTEST.getDefaultSerializer().makeBlock(serializedBlock, serializedBlock.length);
            fail("We expect ProtocolException with the fixed code and OutOfMemoryError with the buggy code, so this is weird");
        } catch (ProtocolException e) {
            //Expected, do nothing
        }
    }*/

}