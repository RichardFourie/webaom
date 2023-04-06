/* (PD) 2003 The Bitzi Corporation
 * Please see http://bitzi.com/publicdomain for more info.
 *
 * $Id: TigerTree.java,v 1.2 2003/04/13 03:22:15 gojomo Exp $
 */
package com.bitzi.util;

import java.security.DigestException;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.ListIterator;

import gnu.crypto.hash.Tiger;

/**
 * Implementation of THEX tree hash algorithm, with Tiger as the internal
 * algorithm (using the approach as revised in December 2002, to add unique
 * prefixes to leaf and node operations)
 *
 * For simplicity, calculates one entire generation before starting on the next.
 * A more space-efficient approach would use a stack, and calculate each node as
 * soon as its children ara available.
 */
public class TigerTree extends MessageDigest {
    private static final int BLOCKSIZE = 1024;
    private static final int HASHSIZE = 24;

    /** 1024 byte buffer */
    private final byte[] buffer;

    /** Buffer offset */
    private int bufferOffset;

    /** Number of bytes hashed until now. */
    private long byteCount;

    /** Internal Tiger MD instance */
    // private MessageDigest tiger;
    private Tiger tiger;

    /** Interim tree node hash values */
    private ArrayList<byte[]> nodes;

    /**
     * Constructor
     */
    public TigerTree() {
        super("TigerTree");
        buffer = new byte[TigerTree.BLOCKSIZE];
        bufferOffset = 0;
        byteCount = 0;

        tiger = new Tiger();
        nodes = new ArrayList<>();
    }

    @Override
    protected int engineGetDigestLength() {
        return TigerTree.HASHSIZE;
    }

    @Override
    protected void engineUpdate(byte in) {
        byteCount = getByteCount() + 1;
        buffer[bufferOffset++] = in;

        if (bufferOffset == TigerTree.BLOCKSIZE) {
            blockUpdate();
            bufferOffset = 0;
        }
    }

    @Override
    protected void engineUpdate(byte[] in, int offset, int length) {
        byteCount = getByteCount() + length;

        int remaining;

        while (length >= (remaining = TigerTree.BLOCKSIZE - bufferOffset)) {
            System.arraycopy(in, offset, buffer, bufferOffset, remaining);
            bufferOffset += remaining;
            blockUpdate();
            length -= remaining;
            offset += remaining;
            bufferOffset = 0;
        }

        System.arraycopy(in, offset, buffer, bufferOffset, length);
        bufferOffset += length;
    }

    @Override
    protected byte[] engineDigest() {
        byte[] hash = new byte[TigerTree.HASHSIZE];

        try {
            engineDigest(hash, 0, TigerTree.HASHSIZE);
        } catch (DigestException e) {
            e.printStackTrace();
            return null;
        }
        return hash;
    }

    @Override
    protected int engineDigest(byte[] buf, int offset, int len) throws DigestException {

        if (len < TigerTree.HASHSIZE) {
            throw new DigestException();
        }

        // hash any remaining fragments
        blockUpdate();

        // composite neighboring nodes together up to top value
        while (nodes.size() > 1) {
            ArrayList<byte[]> newNodes = new ArrayList<>();
            ListIterator<byte[]> iter = nodes.listIterator();

            while (iter.hasNext()) {
                byte[] left = iter.next();

                if (iter.hasNext()) {
                    byte[] right = iter.next();
                    tiger.reset();
                    tiger.update((byte) 1); // node prefix
                    tiger.update(left, 0, left.length);
                    tiger.update(right, 0, right.length);
                    newNodes.add(tiger.digest());
                } else {
                    newNodes.add(left);
                }
            }
            nodes = newNodes;
        }
        System.arraycopy(nodes.get(0), 0, buf, offset, TigerTree.HASHSIZE);
        engineReset();
        return TigerTree.HASHSIZE;
    }

    @Override
    protected void engineReset() {
        bufferOffset = 0;
        byteCount = 0;
        nodes = new ArrayList<>();
        tiger.reset();
    }

    @Override
    public Object clone() throws CloneNotSupportedException {
        throw new CloneNotSupportedException();
    }

    /**
     * Update the internal state with a single block of size 1024 (or less, in final
     * block) from the internal buffer.
     */
    protected void blockUpdate() {
        tiger.reset();
        tiger.update((byte) 0); // leaf prefix
        tiger.update(buffer, 0, bufferOffset);

        if ((bufferOffset == 0) & (nodes.size() > 0)) {
            return; // don't remember a zero-size hash except at very beginning
        }
        byte[] b = tiger.digest();

        nodes.add(b);
    }

    public static String tl(byte[] b) {
        StringBuilder str = new StringBuilder();

        for (int i = 0; i < 24; i++) {
            str.append(b[i] < 0 ? 256 + b[i] : b[i]).append(",");
        }
        return str.toString();
    }

    public long getByteCount() {
        return byteCount;
    }
}
