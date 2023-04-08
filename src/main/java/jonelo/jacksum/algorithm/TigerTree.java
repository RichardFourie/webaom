/**
 *******************************************************************************
 *
 * Jacksum 3.5.0 - a checksum utility in Java
 * Copyright (c) 2001-2023 Dipl.-Inf. (FH) Johann N. Löfflmann,
 * All Rights Reserved, <https://jacksum.net>.
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later
 * version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program. If not, see <https://www.gnu.org/licenses/>.
 *
 *******************************************************************************
 */

/*
 * (PD) 2003 The Bitzi Corporation
 * Please see http://bitzi.com/publicdomain for more info.
 *
 * Basis:
 * TigerTree.java,v 1.9 2006/06/29 23:35:00 sberlin Exp $
 * see also
 * https://www.limewire.org/fisheye/browse/limecvs/core/com/limegroup/gnutella/security/TigerTree.java
 *
 * Modifications by jonelo for Jacksum (GPL):
 * - changed the package name
 * - replaced the MessageDigest with Jacksum's AbstractChecksum
 * - provided a named constructor to be able to calculate both tiger and tiger2
 * - provided getBlockSize to be able to perform calculations with any Hash algorithm that reveals its block size
 * - replaced the cryptix Tiger provider with GNU's implementation
 * - code reformatted
 * - fixed sf change request# 1693872: Decrease the memory requirement of the TigerTree class
 *   http://sourceforge.net/tracker/?func=detail&aid=1693872&group_id=74387&atid=540849
 *   now at https://sourceforge.net/p/jacksum/feature-requests/13/
 */
package jonelo.jacksum.algorithm;

import java.security.DigestException;
import java.security.MessageDigest;
import java.util.ArrayList;

import gnu.crypto.hash.Tiger;

/**
 * Implementation of THEX tree hash algorithm, with any hash algorithm (using
 * the approach as revised in December 2002, to add unique prefixes to leaf and
 * node operations)
 *
 * This more space-efficient approach uses a stack, and calculate each node as
 * soon as its children ara available.
 */
public class TigerTree extends MessageDigest {

    private final static int BLOCKSIZE = 1024;
    private final int HASHSIZE = 24;
    /**
     * a Marker for the Stack
     */
    private final byte[] MARKER = {};
    /**
     * 1024 byte buffer
     */
    private final byte[] buffer;
    /**
     * Buffer offset
     */
    private int bufferOffset;
    /**
     * Number of bytes hashed until now.
     */
    private long byteCount;
    /**
     * Internal Tiger MD instance
     */
    private Tiger tiger;
    /**
     * Interim tree node hash values
     */
    private final ArrayList<byte[]> nodes; // contains <byte[]>

    /**
     * Constructor
     *
     * @param name the name.
     * @throws java.security.NoSuchAlgorithmException if there is no such algorithm.
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
        return HASHSIZE;
    }

    @Override
    protected void engineUpdate(byte in) {
        byteCount += 1;
        buffer[bufferOffset++] = in;
        if (bufferOffset == TigerTree.BLOCKSIZE) {
            blockUpdate();
            bufferOffset = 0;
        }
    }

    @Override
    protected void engineUpdate(byte[] in, int offset, int length) {
        int newOffset = offset;
        int newLength = length;
        byteCount += newLength;
        nodes.ensureCapacity(TigerTree.log2Ceil(byteCount / TigerTree.BLOCKSIZE));

        if (bufferOffset > 0) {
            int remaining = TigerTree.BLOCKSIZE - bufferOffset;
            System.arraycopy(in, newOffset, buffer, bufferOffset, remaining);
            blockUpdate();
            bufferOffset = 0;
            newLength -= remaining;
            newOffset += remaining;
        }

        while (newLength >= TigerTree.BLOCKSIZE) {
            blockUpdate(in, offset, TigerTree.BLOCKSIZE);
            newLength -= TigerTree.BLOCKSIZE;
            newOffset += TigerTree.BLOCKSIZE;
        }

        if (newLength > 0) {
            System.arraycopy(in, newOffset, buffer, 0, newLength);
            bufferOffset = newLength;
        }
    }

    @Override
    protected byte[] engineDigest() {
        byte[] hash = new byte[HASHSIZE];
        try {
            engineDigest(hash, 0, HASHSIZE);
        } catch (@SuppressWarnings("unused") DigestException e) {
            return null;
        }
        return hash;
    }

    @Override
    protected int engineDigest(byte[] buf, int offset, int len) throws DigestException {
        if (len < HASHSIZE) {
            throw new DigestException();
        }

        // hash any remaining fragments
        blockUpdate();

        byte[] ret = collapse();

        // Assert.that(ret != MARKER);
        System.arraycopy(ret, 0, buf, offset, HASHSIZE);
        engineReset();
        return HASHSIZE;
    }

    /**
     * collapse whatever the tree is now to a root.
     */
    private byte[] collapse() {
        byte[] last = null;
        for (int i = 0; i < nodes.size(); i++) {
            byte[] current = nodes.get(i);
            if (current == MARKER) {
                continue;
            }

            if (last == null) {
                last = current;
            } else {
                tiger.reset();
                tiger.update((byte) 1); // node prefix
                tiger.update(current, 0, current.length);
                tiger.update(last, 0, last.length);
                last = tiger.digest();
            }

            nodes.set(i, MARKER);
        }
        // Assert.that(last != null);
        return last;
    }

    @Override
    protected void engineReset() {
        bufferOffset = 0;
        byteCount = 0;
        nodes.clear();
        tiger.reset();
    }

    /**
     * Method overrides MessageDigest.clone()
     *
     * @throws java.lang.CloneNotSupportedException if clone() is not supported.
     * @see java.security.MessageDigest#clone()
     */
    @Override
    public Object clone() throws CloneNotSupportedException {
        throw new CloneNotSupportedException();
    }

    protected void blockUpdate() {
        blockUpdate(buffer, 0, bufferOffset);
    }

    /**
     * Update the internal state with a single block of size 1024 (or less, in final
     * block) from the internal buffer.
     *
     * @param buf the byte buffer.
     * @param pos the position.
     * @param len the length.
     */
    protected void blockUpdate(byte[] buf, int pos, int len) {
        tiger.reset();
        tiger.update((byte) 0); // leaf prefix
        tiger.update(buf, pos, len);
        if ((len == 0) && (nodes.size() > 0)) {
            return; // don't remember a zero-size hash except at very beginning
        }
        byte[] digest = tiger.digest();
        push(digest);
    }

    private void push(byte[] data) {
        byte[] newData = data;
        if (!nodes.isEmpty()) {
            for (int i = 0; i < nodes.size(); i++) {
                byte[] node = nodes.get(i);
                if (node == MARKER) {
                    nodes.set(i, newData);
                    return;
                }

                tiger.reset();
                tiger.update((byte) 1);
                tiger.update(node, 0, node.length);
                tiger.update(newData, 0, newData.length);
                newData = tiger.digest();
                nodes.set(i, MARKER);
            }
        }
        nodes.add(newData);
    }

    // calculates the next n with 2^n > number
    public static int log2Ceil(long number) {
        long newNumber = number;
        int n = 0;
        while (newNumber > 1) {
            newNumber++; // for rounding up.
            newNumber >>>= 1;
            n++;
        }

        return n;
    }
}
