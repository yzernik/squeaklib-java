package io.github.yzernik.squeaklib.core;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class EncodingTest {

    @Test
    public void testEncodeDecode() throws Exception {
        String message = "my message";
        byte[] encodedMsg = Encoding.encodeMessage(message);
        String decodedMsg = Encoding.decodeMessage(encodedMsg);

        assertEquals(encodedMsg.length, Encoding.CONTENT_LENGTH);
        assertEquals(decodedMsg, message);
    }

    @Test
    public void testEncodeDecodeMaximumLength() throws Exception {
        String message = createStringOfLength('*', Encoding.CONTENT_LENGTH);
        byte[] encodedMsg = Encoding.encodeMessage(message);
        String decodedMsg = Encoding.decodeMessage(encodedMsg);

        assertEquals(encodedMsg.length, Encoding.CONTENT_LENGTH);
        assertEquals(decodedMsg, message);
    }

    @Test(expected = EncodingException.class)
    public void testEncodeDecodeAboveMaximumLength() throws Exception {
        String message = createStringOfLength('*', Encoding.CONTENT_LENGTH + 1);
        Encoding.encodeMessage(message);
    }

    private static String createStringOfLength(char c, int n){
        //create new string from char array of required size
        String str = new String(new char[n]);
        //replace all NUL chars '\0' with specified char
        str = str.replace('\0', c);
        return str;
    }

}
