package io.github.yzernik.squeaklib.core;

import org.bitcoinj.core.BitcoinSerializer;
import org.bitcoinj.core.Block;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.ProtocolException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SqueakSerializer extends BitcoinSerializer {
    private static final Logger log = LoggerFactory.getLogger(SqueakSerializer.class);

    /**
     * Constructs a BitcoinSerializer with the given behavior.
     *
     * @param params           networkParams used to create Messages instances and determining packetMagic
     * @param parseRetain      retain the backing byte array of a message for fast reserialization.
     */
    public SqueakSerializer(NetworkParameters params, boolean parseRetain) {
        super(params, parseRetain);
    }

    /**
     * Make a block from the payload. Extension point for alternative
     * serialization format support.
     */
    public Block makeBlock(final byte[] payloadBytes, final int offset, final int length) throws ProtocolException {
        return new Block(getParameters(), payloadBytes, offset, this, length);
    }

    /**
     * Make a squeak from the payload.
     */
    public Squeak makeSqueak(final byte[] payloadBytes, final int offset, final int length) throws ProtocolException {
        return new Squeak(getParameters(), payloadBytes, offset, this, length);
    }

    /**
     * Make a block from the payload, using an offset of zero and the payload
     * length as block length.
     */
    public final Squeak makeSqueak(byte[] payloadBytes) throws ProtocolException {
        return makeSqueak(payloadBytes, 0, payloadBytes.length);
    }

}
