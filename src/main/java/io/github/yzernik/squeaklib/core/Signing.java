package io.github.yzernik.squeaklib.core;

import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptBuilder;
import org.bitcoinj.script.ScriptChunk;
import org.bitcoinj.script.ScriptOpCodes;

public class Signing {

    /**
     * Create the sig script that will be used to verify the squeak.
     * @param signature
     * @param verifyingKeyBytes
     * @return
     */
    public static Script makeSigScript(ECKey.ECDSASignature signature, byte[] verifyingKeyBytes) {
        ScriptBuilder scriptBuilder = new ScriptBuilder();
        scriptBuilder.data(signature.encodeToDER());
        scriptBuilder.data(verifyingKeyBytes);
        return scriptBuilder.build();
    }


    /**
     * Create the pubkey script.
     * @param pubKeyHash
     * @return
     */
    public static Script makePubKeyScript(byte[] pubKeyHash) {
        ScriptBuilder scriptBuilder = new ScriptBuilder();
        scriptBuilder.op(ScriptOpCodes.OP_DUP);
        scriptBuilder.op(ScriptOpCodes.OP_HASH160);
        scriptBuilder.data(pubKeyHash);
        scriptBuilder.op(ScriptOpCodes.OP_EQUALVERIFY);
        scriptBuilder.op(ScriptOpCodes.OP_CHECKSIG);
        return scriptBuilder.build();
    }



}
