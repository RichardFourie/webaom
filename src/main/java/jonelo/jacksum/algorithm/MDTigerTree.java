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

package jonelo.jacksum.algorithm;

import java.security.MessageDigest;

import com.bitzi.util.Base32;

/**
 * A wrapper class that can be used to compute TigerTree
 */
public class MDTigerTree extends AbstractChecksum {

    private MessageDigest md = null;

    public MDTigerTree() {
        md = new TigerTree();
    }

    @Override
    public void reset() {
        md.reset();
    }

    @Override
    public void update(byte[] buffer, int offset, int len) {
        md.update(buffer, offset, len);
    }

    @Override
    public void update(int b) {
        update((byte) b);
    }

    @Override
    public String getHexValue() {
        return Base32.encode(md.digest()).toLowerCase();
    }
}
