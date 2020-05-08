package io.github.yzernik.squeaklib.core;

import org.bitcoinj.core.*;

import javax.annotation.Nullable;
import java.io.IOException;
import java.io.OutputStream;

public class VCH_IV extends ChildMessage {
    public static int CIPHER_BLOCK_LENGTH = 16;

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

    public byte[] getBytes() {
        return bytes;
    }

    /**
     * Returns a reversed copy of the internal byte array.
     */
    public byte[] getReversedBytes() {
        return Utils.reverseBytes(bytes);
    }

    @Override
    public String toString() {
        return Utils.HEX.encode(getReversedBytes());
    }
}
