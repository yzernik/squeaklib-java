package io.github.yzernik.squeaklib.core;

import java.nio.ByteBuffer;
import java.nio.charset.Charset;

public class Encoding {
    private static final int CONTENT_LENGTH = 1120;

    public static byte[] encodeMessage(String s) {
        byte[] bytes = s.getBytes(Charset.forName("utf-8"));
        byte[] ret = new byte[CONTENT_LENGTH];
        ByteBuffer bb = ByteBuffer.wrap(ret);
        bb.put(bytes);
        for (int i = bytes.length; i < CONTENT_LENGTH; i++){
            bb.put((byte) '\00');
        }
        return ret;
    }

    public static String decodeMessage(byte[] bytes) {
        String s = new String(bytes, Charset.forName("utf-8"));
        return s.trim();
    }

}
