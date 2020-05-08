package io.github.yzernik.squeaklib.core;

import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.Sha256Hash;
import org.bitcoinj.core.Transaction;

public class SqueakTransaction extends Transaction {
    private Sha256Hash hash;

    public SqueakTransaction(NetworkParameters params, Sha256Hash hash) {
        super(params);
        this.hash = hash;
    }

    @Override
    public Sha256Hash hashForSignature(int inputIndex, byte[] connectedScript, byte sigHashType) {
        return Sha256Hash.wrapReversed(hash.getBytes());
    }

}
