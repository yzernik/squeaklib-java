package io.github.yzernik.core;

import org.bitcoinj.core.*;
import org.bitcoinj.script.Script;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Arrays;

import org.apache.commons.codec.binary.Hex;


public class Squeak extends Message {

    private static final Logger log = LoggerFactory.getLogger(Squeak.class);

    /** How many bytes are required to represent a block header WITHOUT the trailing 00 length byte. */
    public static final int HEADER_SIZE = 80;

    static final long ALLOWED_TIME_DRIFT = 2 * 60 * 60; // Same value as Bitcoin Core.

    /**
     * A constant shared by the entire network: how large in bytes a block is allowed to be. One day we may have to
     * upgrade everyone to change this, so Bitcoin can continue to grow. For now it exists as an anti-DoS measure to
     * avoid somebody creating a titanically huge but valid block and forcing everyone to download/store it forever.
     */
    public static final int MAX_BLOCK_SIZE = 1 * 1000 * 1000;
    /**
     * A "sigop" is a signature verification operation. Because they're expensive we also impose a separate limit on
     * the number in a block to prevent somebody mining a huge block that has way more sigops than normal, so is very
     * expensive/slow to verify.
     */
    public static final int MAX_BLOCK_SIGOPS = MAX_BLOCK_SIZE / 50;

    /** A value for difficultyTarget (nBits) that allows half of all possible hash solutions. Used in unit testing. */
    public static final long EASIEST_DIFFICULTY_TARGET = 0x207fFFFFL;

    /** Value to use if the block height is unknown */
    public static final int BLOCK_HEIGHT_UNKNOWN = -1;
    /** Height of the first block */
    public static final int BLOCK_HEIGHT_GENESIS = 0;

    public static final long BLOCK_VERSION_GENESIS = 1;
    /** Block version introduced in BIP 34: Height in coinbase */
    public static final long BLOCK_VERSION_BIP34 = 2;
    /** Block version introduced in BIP 66: Strict DER signatures */
    public static final long BLOCK_VERSION_BIP66 = 3;
    /** Block version introduced in BIP 65: OP_CHECKLOCKTIMEVERIFY */
    public static final long BLOCK_VERSION_BIP65 = 4;

    // Fields defined as part of the protocol format.
    private long version;
    private Sha256Hash hashEncContent;
    private Sha256Hash hashReplySqk;
    private Sha256Hash hashBlock;
    private long nBlockHeight;

    // A transaction output has a script used for authenticating that the redeemer is allowed to spend
    // this output.
    private byte[] scriptBytes;
    // The script bytes are parsed and turned into a Script on demand.
    private Script scriptPubKey;
    // These fields are not Bitcoin serialized. They are used for tracking purposes in our wallet
    // only. If set to true, this output is counted towards our balance. If false and spentBy is null the tx output
    // was owned by us and was sent to somebody else. If false and spentBy is set it means this output was owned by
    // us and used in one of our own transactions (eg, because it is a change output).
    private int scriptLen;

    private Sha256Hash hashDataKey;
    private VCH_IV vchIv;

    private long nTime;
    private long nNonce;
    // END OF HEADER


    // TODO: Get rid of all the direct accesses to this field. It's a long-since unnecessary holdover from the Dalvik days.
    /** If null, it means this object holds only the headers. */
    @Nullable
    EncContent encContent;

    @Nullable
    Script scriptSig;

    @Nullable
    VCH_DATA_KEY vchDataKey;

    /** Stores the hash of the block. If null, getHash() will recalculate it. */
    private Sha256Hash hash;

    protected boolean headerBytesValid;
    protected boolean contentBytesValid;

    // Blocks can be encoded in a way that will use more bytes than is optimal (due to VarInts having multiple encodings)
    // MAX_BLOCK_SIZE must be compared to the optimal encoding, not the actual encoding, so when parsing, we keep track
    // of the size of the ideal encoding in addition to the actual message size (which Message needs)
    protected int optimalEncodingMessageSize;

    /**
     * Construct a block object from the Bitcoin wire format.
     * @param params NetworkParameters object.
     * @param payloadBytes the payload to extract the block from.
     * @param offset The location of the first payload byte within the array.
     * @param serializer the serializer to use for this message.
     * @param length The length of message if known.  Usually this is provided when deserializing of the wire
     * as the length will be provided as part of the header.  If unknown then set to Message.UNKNOWN_LENGTH
     * @throws ProtocolException
     */
    public Squeak(NetworkParameters params, byte[] payloadBytes, int offset, MessageSerializer serializer, int length)
            throws ProtocolException {
        super(params, payloadBytes, offset, serializer, length);
    }


    @Override
    protected void parse() throws ProtocolException {
        // header
        cursor = offset;
        version = readUint32();
        hashEncContent = readHash();
        hashReplySqk = readHash();
        System.out.println(hashReplySqk);
        hashBlock = readHash();
        System.out.println(hashBlock);
        nBlockHeight = readUint32();

        // parse the script pubkey
        scriptLen = (int) readVarInt();
        length = cursor - offset + scriptLen;
        scriptBytes = readBytes(scriptLen);

        hashDataKey = readHash();

        // Get the vch_iv
        vchIv = new VCH_IV(params, payload, cursor, this, serializer, UNKNOWN_LENGTH, null);
        cursor += vchIv.getMessageSize();

        nTime = readUint32();
        nNonce = readUint32();
        // Get the hash
        hash = Sha256Hash.wrapReversed(Sha256Hash.hashTwice(payload, offset, cursor - offset));
        headerBytesValid = serializer.isParseRetainMode();

        // transactions
        parseContent(offset + HEADER_SIZE);
        length = cursor - offset;
    }


    /**
     * Parse content from the squeak.
     *
     * @param contentOffset Offset of the transactions within the squeak.
     */
    protected void parseContent(final int contentOffset) throws ProtocolException {
        cursor = contentOffset;
        optimalEncodingMessageSize = HEADER_SIZE;
        if (payload.length == cursor) {
            // This message is just a header, it has no content.
            contentBytesValid = false;
            return;
        }

        // Get the enc content.
        encContent = new EncContent(params, payload, cursor, this, serializer, UNKNOWN_LENGTH, null);
        cursor += encContent.getMessageSize();

        // Get the script sig.
        int scriptLen = (int) readVarInt();
        length = cursor - offset + scriptLen + 4;
        scriptBytes = readBytes(scriptLen);
        scriptSig = new Script(scriptBytes);

        // Get the data key.
        vchDataKey = new VCH_DATA_KEY(params, payload, cursor, this, serializer, UNKNOWN_LENGTH, null);
        cursor += vchDataKey.getMessageSize();

        contentBytesValid = serializer.isParseRetainMode();
    }

    /**
     * Returns the hash of the block (which for a valid, solved block should be below the target) in the form seen on
     * the block explorer. If you call this on block 1 in the mainnet chain
     * you will get "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048".
     */
    public String getHashAsString() {
        return getHash().toString();
    }

    /**
     * Returns the hash of the block (which for a valid, solved block should be
     * below the target). Big endian.
     */
    @Override
    public Sha256Hash getHash() {
        if (hash == null)
            hash = calculateHash();
        return hash;
    }

    /**
     * Calculates the block hash by serializing the block and hashing the
     * resulting bytes.
     */
    private Sha256Hash calculateHash() {
        try {
            ByteArrayOutputStream bos = new UnsafeByteArrayOutputStream(HEADER_SIZE);
            writeHeader(bos);
            return Sha256Hash.wrapReversed(Sha256Hash.hashTwice(bos.toByteArray()));
        } catch (IOException e) {
            throw new RuntimeException(e); // Cannot happen.
        }
    }

    // default for testing
    void writeHeader(OutputStream stream) throws IOException {
        // try for cached write first
        if (headerBytesValid && payload != null && payload.length >= offset + HEADER_SIZE) {
            stream.write(payload, offset, HEADER_SIZE);
            return;
        }
        // fall back to manual write
        Utils.uint32ToByteStreamLE(version, stream);
        stream.write(hashEncContent.getReversedBytes());
        //stream.write(hashReplySqk.getReversedBytes());
        //stream.write(hashBlock.getReversedBytes());
        //Utils.uint32ToByteStreamLE(nBlockHeight, stream);
        //stream.write(scriptBytes);
        //stream.write(hashDataKey.getReversedBytes());
        //vchIv.bitcoinSerializeToStream(stream);
        //Utils.uint32ToByteStreamLE(ntime, stream);
        //Utils.uint32ToByteStreamLE(nNonce, stream);
        //Utils.uint32ToByteStreamLE(nBlockHeight, stream);
    }

    public long getVersion() {
        return version;
    }

    public Sha256Hash getHashEncContent() {
        return hashEncContent;
    }

    public Sha256Hash getHashReplySqk() {
        return hashReplySqk;
    }

    public Sha256Hash getHashBlock() {
        return hashBlock;
    }

    /**
     * Returns a multi-line string containing a description of the contents of
     * the block. Use for debugging purposes only.
     */
    @Override
    public String toString() {
        StringBuilder s = new StringBuilder();
        s.append(" squeak: \n");
        s.append("   hash: ").append(getHashAsString()).append('\n');
        s.append("   version: ").append(version);
        s.append('\n');
        s.append("   hash enc content: ").append(getHashEncContent()).append("\n");
        s.append("   hash reply sqk: ").append(getHashReplySqk()).append("\n");
        s.append("   hash block: ").append(getHashBlock()).append("\n");
        s.append("   block height: ").append(nBlockHeight).append(")\n");
        s.append("   script pub key: ").append(scriptPubKey).append(")\n");
        s.append("   hash data key: ").append(hashDataKey).append(")\n");
        s.append("   vchIv: ").append(vchIv).append("\n");
        s.append("   time: ").append(nTime).append("\n");
        s.append("   nonce: ").append(nNonce).append("\n");
        return s.toString();
    }


    public static class EncContent extends ChildMessage {
        private static int ENC_CONTENT_LENGTH = 1136;
        private byte[] bytes;

        /**
         * Creates a transaction by reading payload starting from offset bytes in. Length of a transaction is fixed.
         * @param params NetworkParameters object.
         * @param payload Bitcoin protocol formatted byte array containing message content.
         * @param offset The location of the first payload byte within the array.
         * @param parent The parent of the transaction.
         * @param setSerializer The serializer to use for this transaction.
         * @param length The length of message if known.  Usually this is provided when deserializing of the wire
         * as the length will be provided as part of the header.  If unknown then set to Message.UNKNOWN_LENGTH
         * @param hashFromHeader Used by BitcoinSerializer. The serializer has to calculate a hash for checksumming so to
         * avoid wasting the considerable effort a set method is provided so the serializer can set it. No verification
         * is performed on this hash.
         * @throws ProtocolException
         */
        public EncContent(NetworkParameters params, byte[] payload, int offset, @Nullable Message parent,
                           MessageSerializer setSerializer, int length, @Nullable byte[] hashFromHeader) throws ProtocolException {
            super(params, payload, offset, parent, setSerializer, length);
            /* TODO: cache the content hash
            if (hashFromHeader != null) {
                cachedWTxId = Sha256Hash.wrapReversed(hashFromHeader);
                if (!hasWitnesses())
                    cachedTxId = cachedWTxId;
            }
            */
        }

        @Override
        protected void parse() throws ProtocolException {
            bytes = readBytes(ENC_CONTENT_LENGTH);
            length = ENC_CONTENT_LENGTH;
        }

        protected void bitcoinSerializeToStream(OutputStream stream) throws IOException {
            assert bytes.length == ENC_CONTENT_LENGTH;
            stream.write(bytes);
        }
    }

    public static class VCH_IV extends ChildMessage {
        private static int CIPHER_BLOCK_LENGTH = 16;
        private byte[] bytes;

        public VCH_IV(NetworkParameters params, byte[] payload, int offset, @Nullable Message parent,
                            MessageSerializer setSerializer, int length, @Nullable byte[] hashFromHeader) throws ProtocolException {
            super(params, payload, offset, parent, setSerializer, length);
        }

        @Override
        protected void parse() throws ProtocolException {
            bytes = readBytes(CIPHER_BLOCK_LENGTH);
            length = CIPHER_BLOCK_LENGTH;
        }

        protected void bitcoinSerializeToStream(OutputStream stream) throws IOException {
            assert bytes.length == CIPHER_BLOCK_LENGTH;
            stream.write(bytes);
        }
    }


    public static class VCH_DATA_KEY extends ChildMessage {
        private static int DATA_KEY_LENGTH = 32;
        private byte[] bytes;

        /**
         * Creates a transaction by reading payload starting from offset bytes in. Length of a transaction is fixed.
         * @param params NetworkParameters object.
         * @param payload Bitcoin protocol formatted byte array containing message content.
         * @param offset The location of the first payload byte within the array.
         * @param parent The parent of the transaction.
         * @param setSerializer The serializer to use for this transaction.
         * @param length The length of message if known.  Usually this is provided when deserializing of the wire
         * as the length will be provided as part of the header.  If unknown then set to Message.UNKNOWN_LENGTH
         * @param hashFromHeader Used by BitcoinSerializer. The serializer has to calculate a hash for checksumming so to
         * avoid wasting the considerable effort a set method is provided so the serializer can set it. No verification
         * is performed on this hash.
         * @throws ProtocolException
         */
        public VCH_DATA_KEY(NetworkParameters params, byte[] payload, int offset, @Nullable Message parent,
                          MessageSerializer setSerializer, int length, @Nullable byte[] hashFromHeader) throws ProtocolException {
            super(params, payload, offset, parent, setSerializer, length);
            /* TODO: cache the data key hash
            if (hashFromHeader != null) {
                cachedWTxId = Sha256Hash.wrapReversed(hashFromHeader);
                if (!hasWitnesses())
                    cachedTxId = cachedWTxId;
            }
            */
        }

        @Override
        protected void parse() throws ProtocolException {
            bytes = readBytes(DATA_KEY_LENGTH);
            length = DATA_KEY_LENGTH;
        }

        protected void bitcoinSerializeToStream(OutputStream stream) throws IOException {
            assert bytes.length == DATA_KEY_LENGTH;
            stream.write(bytes);
        }
    }
}
