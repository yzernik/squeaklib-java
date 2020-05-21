package io.github.yzernik.squeaklib.core;


public class SqueakException extends RuntimeException {
    public SqueakException(String msg) {
        super(msg);
    }

    public SqueakException(Exception e) {
        super(e);
    }

    public SqueakException(String msg, Throwable t) {
        super(msg, t);
    }

}
