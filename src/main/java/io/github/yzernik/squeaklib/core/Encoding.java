package io.github.yzernik.squeaklib.core;

import java.nio.ByteBuffer;
import java.nio.charset.Charset;

public class Encoding {
    public static final int CONTENT_LENGTH = 1120;
    private static final Charset CHARSET = Charset.forName("utf-8");

    public static byte[] encodeMessage(String s) throws EncodingException {
        byte[] bytes = s.getBytes(CHARSET);
        if (bytes.length > CONTENT_LENGTH) {
            throw new EncodingException("Encoded string input length " + bytes.length + " is larger than maximum " + CONTENT_LENGTH);
        }
        byte[] ret = new byte[CONTENT_LENGTH];
        ByteBuffer bb = ByteBuffer.wrap(ret);
        bb.put(bytes);
        for (int i = bytes.length; i < CONTENT_LENGTH; i++){
            bb.put((byte) '\00');
        }
        return ret;
    }

    public static String decodeMessage(byte[] bytes) {
        String s = new String(bytes, CHARSET);
        return s.trim();
    }

}
