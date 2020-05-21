package io.github.yzernik.squeaklib.core;


public class EncodingException extends SqueakException {
    public EncodingException(String msg) {
        super(msg);
    }

    public EncodingException(Exception e) {
        super(e);
    }

    public EncodingException(String msg, Throwable t) {
        super(msg, t);
    }

}
