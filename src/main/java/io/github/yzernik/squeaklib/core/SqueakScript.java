package io.github.yzernik.squeaklib.core;

import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.Sha256Hash;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.Utils;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptError;
import org.bitcoinj.script.ScriptException;

import java.util.LinkedList;
import java.util.List;
import java.util.Set;


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
