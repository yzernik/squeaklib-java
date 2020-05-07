package io.github.yzernik.core;

import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.Sha256Hash;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.Utils;
import org.bitcoinj.script.*;

import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import static org.bitcoinj.script.ScriptOpCodes.OP_16;


public class SqueakScript extends Script {

    private static final int MAX_OPS_PER_SCRIPT = 201;
    private static final int MAX_STACK_SIZE = 1000;
    private static final int MAX_PUBKEYS_PER_MULTISIG = 20;
    private static final int MAX_SCRIPT_SIZE = 10000;

    public SqueakScript(byte[] programBytes) throws ScriptException {
        super(programBytes);
    }

    public SqueakScript(byte[] programBytes, long creationTimeSeconds) throws ScriptException {
        super(programBytes, creationTimeSeconds);
    }


    /**
     * Verifies that this script (interpreted as a scriptSig) correctly spends the given scriptPubKey.
     * @param squeakHash The hash of the squeak.
     * @param scriptPubKey The connected scriptPubKey containing the conditions needed to claim the value.
     * @param verifyFlags Each flag enables one validation rule.
     */
    public void correctlyAuthors(NetworkParameters params, Sha256Hash squeakHash, Script scriptPubKey,
                                 Set<VerifyFlag> verifyFlags) throws ScriptException {
        // Clone the transaction because executing the script involves editing it, and if we die, we'll leave
        // the tx half broken (also it's not so thread safe to work on it directly.
        Transaction tx = new SqueakTransaction(params, squeakHash);

        if (getProgram().length > MAX_SCRIPT_SIZE || scriptPubKey.getProgram().length > MAX_SCRIPT_SIZE)
            throw new ScriptException(ScriptError.SCRIPT_ERR_SCRIPT_SIZE, "Script larger than 10,000 bytes");

        LinkedList<byte[]> stack = new LinkedList<>();
        LinkedList<byte[]> p2shStack = null;

        executeScript(tx, 0, this, stack, verifyFlags);
        if (verifyFlags.contains(VerifyFlag.P2SH))
            p2shStack = new LinkedList<>(stack);
        executeScript(tx, 0, scriptPubKey, stack, verifyFlags);

        if (stack.size() == 0)
            throw new ScriptException(ScriptError.SCRIPT_ERR_EVAL_FALSE, "Stack empty at end of script execution.");

        List<byte[]> stackCopy = new LinkedList<>(stack);
        if (!castToBool(stack.pollLast()))
            throw new ScriptException(ScriptError.SCRIPT_ERR_EVAL_FALSE,
                    "Script resulted in a non-true stack: " + Utils.toString(stackCopy));

        // P2SH is pay to script hash. It means that the scriptPubKey has a special form which is a valid
        // program but it has "useless" form that if evaluated as a normal program always returns true.
        // Instead, miners recognize it as special based on its template - it provides a hash of the real scriptPubKey
        // and that must be provided by the input. The goal of this bizarre arrangement is twofold:
        //
        // (1) You can sum up a large, complex script (like a CHECKMULTISIG script) with an address that's the same
        //     size as a regular address. This means it doesn't overload scannable QR codes/NFC tags or become
        //     un-wieldy to copy/paste.
        // (2) It allows the working set to be smaller: nodes perform best when they can store as many unspent outputs
        //     in RAM as possible, so if the outputs are made smaller and the inputs get bigger, then it's better for
        //     overall scalability and performance.

        // TODO: Check if we can take out enforceP2SH if there's a checkpoint at the enforcement block.
        if (verifyFlags.contains(VerifyFlag.P2SH) && ScriptPattern.isP2SH(scriptPubKey)) {
            for (ScriptChunk chunk : chunks)
                if (chunk.isOpCode() && chunk.opcode > OP_16)
                    throw new ScriptException(ScriptError.SCRIPT_ERR_SIG_PUSHONLY, "Attempted to spend a P2SH scriptPubKey with a script that contained script ops");

            byte[] scriptPubKeyBytes = p2shStack.pollLast();
            Script scriptPubKeyP2SH = new Script(scriptPubKeyBytes);

            executeScript(tx, 0, scriptPubKeyP2SH, p2shStack, verifyFlags);

            if (p2shStack.size() == 0)
                throw new ScriptException(ScriptError.SCRIPT_ERR_EVAL_FALSE, "P2SH stack empty at end of script execution.");

            List<byte[]> p2shStackCopy = new LinkedList<>(p2shStack);
            if (!castToBool(p2shStack.pollLast()))
                throw new ScriptException(ScriptError.SCRIPT_ERR_EVAL_FALSE,
                        "P2SH script execution resulted in a non-true stack: " + Utils.toString(p2shStackCopy));
        }
    }

    private static boolean castToBool(byte[] data) {
        for (int i = 0; i < data.length; i++)
        {
            // "Can be negative zero" - Bitcoin Core (see OpenSSL's BN_bn2mpi)
            if (data[i] != 0)
                return !(i == data.length - 1 && (data[i] & 0xFF) == 0x80);
        }
        return false;
    }

}
