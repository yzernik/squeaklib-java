package io.github.yzernik.squeaklib.core;

import org.bitcoinj.core.ECKey;

import java.math.BigInteger;

public class SqueakSignature extends ECKey.ECDSASignature {

    public SqueakSignature(BigInteger r, BigInteger s) {
        super(r, s);
    }
}
