package io.github.yzernik.squeaklib.core;

import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.Sha256Hash;
import org.bitcoinj.core.Transaction;

/**
 * <p>Not a real transaction. This is used as a dummy transaction
 * so that `executeCheckSig` method can be used with the hash
 * of the given squeak.</p>
 */
public class SqueakTransaction extends Transaction {
    private Sha256Hash hash;

    public SqueakTransaction(NetworkParameters params, Sha256Hash hash) {
        super(params);
        this.hash = hash;
    }

    @Override
    public Sha256Hash hashForSignature(int inputIndex, byte[] connectedScript, byte sigHashType) {
        // The hash needs to be reversed before it can be used
        // in a signature because it is stored as a big-endian.
        return Sha256Hash.wrapReversed(hash.getBytes());
    }

}
