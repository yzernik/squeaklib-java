package io.github.yzernik.squeaklib.core;

public class EncryptionException extends SqueakException {
    public EncryptionException(String msg) {
        super(msg);
    }

    public EncryptionException(Exception e) {
        super(e);
    }

    public EncryptionException(String msg, Throwable t) {
        super(msg, t);
    }

}
