package io.github.yzernik.squeaklib.core;

import java.nio.ByteBuffer;
import java.nio.charset.Charset;

public class Encoding {
    private static final int CONTENT_LENGTH = 1120;
    private static final Charset CHARSET = Charset.forName("utf-8");

    public static byte[] encodeMessage(String s) {
        if (s.length() > CONTENT_LENGTH) {
            throw new EncodingException("String input length " + s.length() + " is larger than maximum " + CONTENT_LENGTH);
        }

        byte[] bytes = s.getBytes(CHARSET);
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
