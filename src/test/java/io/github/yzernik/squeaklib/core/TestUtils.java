package io.github.yzernik.squeaklib.core;

import java.security.SecureRandom;

public class TestUtils {

    public static byte[] generateRandomContent() {
        SecureRandom random = new SecureRandom();
        byte bytes[] = new byte[Encryption.CONTENT_LENGTH];
        random.nextBytes(bytes);
        return bytes;
    }

}
