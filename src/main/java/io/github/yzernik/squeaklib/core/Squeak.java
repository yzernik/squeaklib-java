package io.github.yzernik.squeaklib.core;

import org.bitcoinj.core.*;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.ref.WeakReference;
import java.nio.charset.Charset;
import java.util.EnumSet;

import static org.bitcoinj.core.Utils.HEX;


public class Squeak extends Message {

    private static final Logger log = LoggerFactory.getLogger(Squeak.class);

    /** How many bytes are required to represent a block header WITHOUT the trailing 00 length byte. */
    public static final int HEADER_SIZE = 186;
    public static final int IV_SIZE = 16;
    public static final int DATA_KEY_SIZE = 32;
    public static final int ENC_CONTENT_SIZE = 1136;
    public static final int CONTENT_SIZE = 1120;

    /** Value to use if the block height is unknown */
    public static final int BLOCK_HEIGHT_UNKNOWN = -1;
    /** Height of the first block */
    public static final int BLOCK_HEIGHT_GENESIS = 0;

    public static final long SQUEAK_VERSION_ALPHA = 1;

    // Fields defined as part of the protocol format.
    private long version;
    private Sha256Hash hashEncContent;
    private Sha256Hash hashReplySqk;
    private Sha256Hash hashBlock;
    private long nBlockHeight;

    // A transaction output has a script used for authenticating that the redeemer is allowed to spend
    // this output.
    private byte[] scriptPubKeyBytes;
    // The script bytes are parsed and turned into a Script on demand.
    private Script scriptPubKey;
    // These fields are not Bitcoin serialized. They are used for tracking purposes in our wallet
    // only. If set to true, this output is counted towards our balance. If false and spentBy is null the tx output
    // was owned by us and was sent to somebody else. If false and spentBy is set it means this output was owned by
    // us and used in one of our own transactions (eg, because it is a change output).
    private int scriptLen;

    private Sha256Hash hashDataKey;
    private byte[] vchIv;

    private long nTime;
    private long nNonce;
    // END OF HEADER


    // TODO: Get rid of all the direct accesses to this field. It's a long-since unnecessary holdover from the Dalvik days.
    /** If null, it means this object holds only the headers. */
    @Nullable
    byte[] encContent;

    @Nullable
    private byte[] scriptSigBytes;

    // The script bytes are parsed and turned into a Script on demand.
    @Nullable
    private WeakReference<SqueakScript> scriptSig;

    @Nullable
    byte[] vchDataKey;

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

    public Squeak(NetworkParameters params, Sha256Hash hashEncContent, Sha256Hash hashReplySqk, Sha256Hash hashBlock, long nBlockHeight, byte[] scriptPubKeyBytes, Sha256Hash hashDataKey, byte[] vchIv, long nTime, long nNonce, byte[] encContent, byte[] vchDataKey)
            throws ProtocolException {
        super(params);
        // Set up a few basic things. We are not complete after this though.
        this.version = SQUEAK_VERSION_ALPHA;

        this.hashEncContent = hashEncContent;
        this.hashReplySqk = hashReplySqk;
        this.hashBlock = hashBlock;
        this.nBlockHeight = nBlockHeight;
        this.scriptPubKeyBytes = scriptPubKeyBytes;
        this.hashDataKey = hashDataKey;
        this.vchIv = vchIv;
        this.nTime = nTime;
        this.nNonce = nNonce;
        headerBytesValid = serializer.isParseRetainMode();

        // content
        this.encContent = encContent;
        this.scriptSigBytes = scriptPubKeyBytes;
        this.vchDataKey = vchDataKey;

        contentBytesValid = serializer.isParseRetainMode();

        length = HEADER_SIZE;
    }

    /** Special case constructor, used for the genesis node, cloneAsHeader and unit tests. */
    public Squeak(NetworkParameters params, long setVersion)
            throws ProtocolException {
        super(params);
        // Set up a few basic things. We are not complete after this though.
        version = setVersion;
        length = HEADER_SIZE;
    }


    @Override
    protected void parse() throws ProtocolException {
        // header
        cursor = offset;
        version = readUint32();
        hashEncContent = readHash();
        hashReplySqk = readHash();
        hashBlock = readHash();
        nBlockHeight = readUint32();

        // parse the script pubkey
        scriptLen = (int) readVarInt();
        length = cursor - offset + scriptLen;
        scriptPubKeyBytes = readBytes(scriptLen);

        hashDataKey = readHash();

        // Get the vch_iv
        vchIv = readBytes(IV_SIZE);

        nTime = readUint32();
        nNonce = readUint32();
        // Get the hash
        // TODO: uncomment.
        // hash = Sha256Hash.wrapReversed(Sha256Hash.hashTwice(payload, offset, cursor - offset));
        headerBytesValid = serializer.isParseRetainMode();

        // content
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
        encContent = readBytes(ENC_CONTENT_SIZE);

        // Get the script sig.
        int scriptLen = (int) readVarInt();
        length = cursor - offset + scriptLen + 4;
        scriptSigBytes = readBytes(scriptLen);
        // TODO: Maybe uncomment.
        // scriptSig = new Script(scriptSigBytes);

        // Get the data key.
        vchDataKey = readBytes(DATA_KEY_SIZE);

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

    /** Returns a copy of the squeak, but without any content. */
    public Squeak cloneAsHeader() {
        Squeak squeak = new Squeak(params, SQUEAK_VERSION_ALPHA);
        copySqueakHeaderTo(squeak);
        return squeak;
    }

    /** Copy the squeak without content into the provided empty squeak. */
    protected final void copySqueakHeaderTo(final Squeak squeak) {
        squeak.nNonce = nNonce;
        squeak.hashEncContent = hashEncContent;
        squeak.hashReplySqk = hashReplySqk;
        squeak.hashBlock = hashBlock;
        squeak.nBlockHeight = nBlockHeight;
        squeak.scriptPubKeyBytes = scriptPubKeyBytes;
        squeak.scriptSigBytes = scriptSigBytes;
        squeak.hashDataKey = hashDataKey;
        squeak.vchIv = vchIv;
        squeak.version = version;
        squeak.nTime = nTime;
        squeak.encContent = null;
        squeak.scriptSig = null;
        squeak.vchDataKey = null;
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
        stream.write(hashReplySqk.getReversedBytes());
        stream.write(hashBlock.getReversedBytes());
        Utils.uint32ToByteStreamLE(nBlockHeight, stream);
        stream.write(new VarInt(scriptLen).encode());
        stream.write(scriptPubKeyBytes);
        stream.write(hashDataKey.getReversedBytes());
        stream.write(vchIv);
        Utils.uint32ToByteStreamLE(nTime, stream);
        Utils.uint32ToByteStreamLE(nNonce, stream);
    }

    // default for testing
    void writeHeaderManual(OutputStream stream) throws IOException {
        // fall back to manual write
        Utils.uint32ToByteStreamLE(version, stream);
        stream.write(hashEncContent.getReversedBytes());
        stream.write(hashReplySqk.getReversedBytes());
        stream.write(hashBlock.getReversedBytes());
        Utils.uint32ToByteStreamLE(nBlockHeight, stream);
        stream.write(new VarInt(scriptLen).encode());
        stream.write(scriptPubKeyBytes);
        stream.write(hashDataKey.getReversedBytes());
        stream.write(vchIv);
        Utils.uint32ToByteStreamLE(nTime, stream);
        Utils.uint32ToByteStreamLE(nNonce, stream);
    }

    private void writeContent(OutputStream stream) throws IOException {
        // TODO
    }

    @Override
    protected void bitcoinSerializeToStream(OutputStream stream) throws IOException {
        writeHeader(stream);
        // We may only have enough data to write the header.
        writeContent(stream);
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

    public Script getScriptPubKey() throws ScriptException {
        if (scriptPubKey == null) {
            scriptPubKey = new Script(scriptPubKeyBytes);
        }
        return scriptPubKey;
    }

    /**
     * Get the address for the author of this squeak.
     * @return
     * @throws ScriptException
     */
    public Address getAddress() throws ScriptException {
        Script pubkey = getScriptPubKey();
        return pubkey.getToAddress(params);
    }

    public Sha256Hash getHashDataKey() throws ScriptException {
        return hashDataKey;
    }

    public byte[] getVchIv() throws ScriptException {
        return vchIv;
    }

    public long getTime() throws ScriptException {
        return nTime;
    }


    public long getNonce() throws ScriptException {
        return nNonce;
    }

    /**
     * Returns the script that is fed to the referenced output (scriptPubKey) script in order to satisfy it: usually
     * contains signatures and maybe keys, but can contain arbitrary data if the output script accepts it.
     */
    public SqueakScript getScriptSig() throws ScriptException {
        // Transactions that generate new coins don't actually have a script. Instead this
        // parameter is overloaded to be something totally different.
        SqueakScript script = scriptSig == null ? null : scriptSig.get();
        if (script == null) {
            script = new SqueakScript(scriptSigBytes);
            scriptSig = new WeakReference<>(script);
        }
        return script;
    }

    /**
     * Set the sig script.
     */
    public void setScriptSig(Script script) throws ScriptException {
        scriptSig = null;
        scriptSigBytes = script.getProgram();
    }

    /**
     * Set the data key.
     */
    public void setDataKey(byte[] dataKey) throws ScriptException {
        vchDataKey = dataKey;
    }

    /**
     * Clear the data key.
     */
    public void clearDataKey() throws ScriptException {
        vchDataKey = null;
    }

    public byte[] getDataKey() {
        return vchDataKey;
    }

    public byte[] getEncContent() {
        return encContent;
    }

    /**
     * Verifies both the header and that the content hashes correctly.
     *
     * @throws VerificationException if there was an error verifying the block.
     */
    public void verify() throws VerificationException {
        verify(false);
    }

    /**
     * Verifies both the header and that the content hashes correctly.
     *
     * @param skipDecryptionCheck Don't check if the data key is valid or present.
     * @throws VerificationException if there was an error verifying the block.
     */
    public void verify(boolean skipDecryptionCheck) throws VerificationException {
        verifyHeader();
        verifyContent();
        if (!skipDecryptionCheck)
            verifyDataKey();
    }

    /**
     * Checks the squeak data to ensure it follows the rules laid out in the network parameters.
     *
     * @throws VerificationException
     */
    public void verifyHeader() throws VerificationException {
        // Prove that this squeak is OK.
        checkPubKey();
    }

    private void checkPubKey() {
        try {
            getAddress();
        } catch (ScriptException e) {
            throw new VerificationException("Unable to generate address for squeak: " + e);
        }
    }

    /**
     * Checks the squeak contents
     *
     * @throws VerificationException if there was an error verifying the squeak.
     */
    public void verifyContent() throws VerificationException {
        // Content length check
        if (encContent.length != ENC_CONTENT_SIZE)
            throw new VerificationException("verifyContent() : encContent length does not match the required length");

        // Content hash check
        Sha256Hash encContentHash = Sha256Hash.wrapReversed(Sha256Hash.hashTwice(encContent));
        if (!encContentHash.equals(hashEncContent))
            throw new VerificationException("verifyContent() : hashEncContent does not match hash of encContent");

        // Squeak signature check
        SqueakScript sigScript = getScriptSig();
        Sha256Hash squeakHash = getHash();
        Script pubkeyScript = getScriptPubKey();
        try {
            sigScript.correctlyAuthors(params, squeakHash, pubkeyScript, EnumSet.noneOf(Script.VerifyFlag.class));
        } catch (ScriptException e) {
            throw new VerificationException("verifyContent() : invalid signature for the given squeak");
        }
    }


    /**
     * Checks the data key
     *
     * @throws VerificationException if there was an error verifying the data key.
     */
    public void verifyDataKey() throws VerificationException {
        byte[] dataKey = getDataKey();
        Sha256Hash dataKeyHash = getHashDataKey();
        Sha256Hash hashedDataKey;

        try {
            hashedDataKey = hashDataKey(dataKey);
        } catch (Exception e) {
            throw new VerificationException("verifyContent() : invalid data key for the given squeak");
        }

        if (!dataKeyHash.equals(hashedDataKey))
            throw new VerificationException("verifyContent() : invalid data key for the given squeak");
    }

    private static Sha256Hash hashDataKey(byte[] dataKey) throws Exception{
        return Sha256Hash.wrapReversed(Sha256Hash.hash(dataKey));
    }

    public byte[] getDecryptedContent() throws Exception {
        byte[] dataKey = getDataKey();
        byte[] iv = getVchIv();
        byte[] cipherText = getEncContent();
        return Encryption.decryptContent(dataKey, iv, cipherText);
    }

    public String getDecryptedContentStr() throws Exception {
        return Encoding.decodeMessage(getDecryptedContent());
    }

    /**
     * Make a new squeak.
     *
     * @param signingKey
     * @param content
     * @param blockHeight
     * @param timestamp
     * @param replyTo
     * @return
     */
    public static Squeak makeSqueak(NetworkParameters params, ECKey signingKey, byte[] content, int blockHeight, Sha256Hash blockHash, long timestamp, Sha256Hash replyTo) throws Exception {
        byte[] dataKey = Encryption.generateDataKey();
        byte[] iv = Encryption.generateIV();
        byte[] encContent = Encryption.encryptContent(dataKey, iv, content);
        Sha256Hash dataKeyHash = hashDataKey(dataKey);
        long nonce = Encryption.generateNonce();
        byte[] pubKeyBytes = signingKey.getPubKey();
        byte[] pubKeyHash = signingKey.getPubKeyHash();
        Script pubKeyScript = Signing.makePubKeyScript(pubKeyHash);
        Squeak squeak = new Squeak(
                params,
                Sha256Hash.wrapReversed(Sha256Hash.hashTwice(encContent)),
                replyTo,
                blockHash,
                blockHeight,
                pubKeyScript.getProgram(),
                dataKeyHash,
                iv,
                timestamp,
                nonce,
                encContent,
                dataKey
        );
        Script sigScript = squeak.signSqueak(signingKey, pubKeyBytes);
        squeak.setScriptSig(sigScript);
        return squeak;
    }

    public static Squeak makeSqueakFromStr(NetworkParameters params, ECKey signingKey, String message, int blockHeight, Sha256Hash blockHash, long timestamp, Sha256Hash replyTo) throws Exception {
        return makeSqueak(
                params,
                signingKey,
                Encoding.encodeMessage(message),
                blockHeight,
                blockHash,
                timestamp,
                replyTo);
    }

    /**
     * Sign the squeak and return the sig script.
     * @param signingKey
     * @param pubKeyBytes
     * @return
     */
    public Script signSqueak(ECKey signingKey, byte[] pubKeyBytes) {
        Sha256Hash squeakHash = Sha256Hash.wrap(getHash().getReversedBytes());
        ECKey.ECDSASignature signature = signingKey.sign(squeakHash);
        return Signing.makeSigScript(signature, pubKeyBytes);
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
        s.append("   block height: ").append(nBlockHeight).append("\n");
        s.append("   script pub key: ").append(getScriptPubKey()).append("\n");
        s.append("   hash data key: ").append(getHashDataKey()).append("\n");
        s.append("   vchIv: ").append(HEX.encode(getVchIv())).append("\n");
        s.append("   time: ").append(nTime).append("\n");
        s.append("   nonce: ").append(getNonce()).append("\n");
        return s.toString();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        return getHash().equals(((Squeak)o).getHash());
    }

    @Override
    public int hashCode() {
        return getHash().hashCode();
    }

}
