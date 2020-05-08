package io.github.yzernik.squeaklib.core;

import org.bitcoinj.core.ECKey;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptBuilder;

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
        scriptBuilder.op(0x00000001); // SIGHASH_ALL
        scriptBuilder.data(verifyingKeyBytes);
        return scriptBuilder.build();
    }



}
