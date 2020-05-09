package io.github.yzernik.squeaklib.core;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class EncodingTest {

    @Test
    public void testEncodeDecode() throws Exception {
        String message = "my message";
        byte[] encodedMsg = Encoding.encodeMessage(message);
        String decodedMsg = Encoding.decodeMessage(encodedMsg);

        assertEquals(decodedMsg, message);
    }

}
