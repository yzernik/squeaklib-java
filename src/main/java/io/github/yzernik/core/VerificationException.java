package io.github.yzernik.core;

public class VerificationException extends RuntimeException {
    public VerificationException(String msg) {
        super(msg);
    }

    public VerificationException(Exception e) {
        super(e);
    }

    public VerificationException(String msg, Throwable t) {
        super(msg, t);
    }

    public static class EmptyInputsOrOutputs extends org.bitcoinj.core.VerificationException {
        public EmptyInputsOrOutputs() {
            super("Transaction had no inputs or no outputs.");
        }
    }

    public static class LargerThanMaxBlockSize extends org.bitcoinj.core.VerificationException {
        public LargerThanMaxBlockSize() {
            super("Transaction larger than MAX_BLOCK_SIZE");
        }
    }

    public static class DuplicatedOutPoint extends org.bitcoinj.core.VerificationException {
        public DuplicatedOutPoint() {
            super("Duplicated outpoint");
        }
    }

    public static class NegativeValueOutput extends org.bitcoinj.core.VerificationException {
        public NegativeValueOutput() {
            super("Transaction output negative");
        }
    }

    public static class ExcessiveValue extends org.bitcoinj.core.VerificationException {
        public ExcessiveValue() {
            super("Total transaction output value greater than possible");
        }
    }


    public static class CoinbaseScriptSizeOutOfRange extends org.bitcoinj.core.VerificationException {
        public CoinbaseScriptSizeOutOfRange() {
            super("Coinbase script size out of range");
        }
    }


    public static class BlockVersionOutOfDate extends org.bitcoinj.core.VerificationException {
        public BlockVersionOutOfDate(final long version) {
            super("Block version #"
                    + version + " is outdated.");
        }
    }

    public static class UnexpectedCoinbaseInput extends org.bitcoinj.core.VerificationException {
        public UnexpectedCoinbaseInput() {
            super("Coinbase input as input in non-coinbase transaction");
        }
    }

    public static class CoinbaseHeightMismatch extends org.bitcoinj.core.VerificationException {
        public CoinbaseHeightMismatch(final String message) {
            super(message);
        }
    }
}
