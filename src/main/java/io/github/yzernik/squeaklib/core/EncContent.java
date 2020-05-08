package io.github.yzernik.squeaklib.core;

import org.bitcoinj.core.*;

import javax.annotation.Nullable;
import java.io.IOException;
import java.io.OutputStream;

public class EncContent extends ChildMessage {
    public static int ENC_CONTENT_LENGTH = 1136;
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

    public byte[] getBytes() {
        return bytes;
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
