package io.github.yzernik.squeaklib.core;


public class SigningException extends RuntimeException {
    public SigningException(String msg) {
        super(msg);
    }

    public SigningException(Exception e) {
        super(e);
    }

    public SigningException(String msg, Throwable t) {
        super(msg, t);
    }

}
