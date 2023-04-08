/*


  Jacksum 3.5.0 - a checksum utility in Java
  Copyright (c) 2001-2023 Dipl.-Inf. (FH) Johann N. Löfflmann,
  All Rights Reserved, <https://jacksum.net>.

  This program is free software: you can redistribute it and/or modify it under
  the terms of the GNU General Public License as published by the Free Software
  Foundation, either version 3 of the License, or (at your option) any later
  version.

  This program is distributed in the hope that it will be useful, but WITHOUT
  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
  FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
  details.

  You should have received a copy of the GNU General Public License along with
  this program. If not, see <https://www.gnu.org/licenses/>.


 */
/*

  Edonkey is an implementation of the AbstractChecksum in order to calculate a
  message digest in the form of edonkey/emule hash. It uses the MD4 algorithm
  as an auxiliary algorithm, from the GNU crypto project,
  http://www.gnu.org/software/classpathx/crypto

  */
package jonelo.jacksum.algorithm;

import gnu.crypto.hash.IMessageDigest;
import gnu.crypto.hash.MD4;

/**
 * A class that can be used to compute the eDonkey of a data stream.
 */
public class Edonkey extends AbstractChecksum {

    private final IMessageDigest md4;
    private final IMessageDigest md4final;

    private final static int BLOCKSIZE = 9728000; // 9500 * 1024;
    private final byte[] edonkeyHash = new byte[16]; // 16 bytes, 128 bits

    /**
     * Creates a new Edonkey object.
     *
     */
    public Edonkey() {
        md4 = new MD4();
        md4final = new MD4();
    }

    @Override
    public void reset() {
        md4.reset();
        md4final.reset();
        length = 0;
    }

    @Override
    public void update(byte b) {
        md4.update(b);
        length++;

        if ((length % Edonkey.BLOCKSIZE) == 0) {
            System.arraycopy(md4.digest(), 0, edonkeyHash, 0, 16);
            md4final.update(edonkeyHash, 0, 16);
            md4.reset();
        }
    }

    @Override
    public void update(byte[] buffer, int offset, int len) {
        int zuSchreiben = len - offset; // this is XXX
        int passed = (int) (length % Edonkey.BLOCKSIZE);
        int platz = Edonkey.BLOCKSIZE - passed;

        // |___________XXX....|_____
        if (platz > zuSchreiben) {
            md4.update(buffer, offset, len);
            length += len;
        } else // |_______________XXX|_____
        if (platz == zuSchreiben) {
            md4.update(buffer, offset, len);
            length += len;
            System.arraycopy(md4.digest(), 0, edonkeyHash, 0, 16);
            md4final.update(edonkeyHash, 0, 16);
            md4.reset();
        } else // |________________XX|X____
        if (platz < zuSchreiben) {
            md4.update(buffer, offset, platz);
            length += platz;

            System.arraycopy(md4.digest(), 0, edonkeyHash, 0, 16);
            md4final.update(edonkeyHash, 0, 16);
            md4.reset();

            md4.update(buffer, offset + platz, zuSchreiben - platz);
            length += zuSchreiben - platz;
        }

    }

    @Override
    public String getHexValue() {

        if (length < Edonkey.BLOCKSIZE) {
            // if only one block, partial md4 hash = final hash
            System.arraycopy(md4.digest(), 0, edonkeyHash, 0, 16);
        } else {
            // let's copy the md4final object first
            // so we can launch getHexValue multiple times
            IMessageDigest md4temp = (IMessageDigest) md4final.clone();
            // if more then one block, final hash = hash of all partial hashes
            md4temp.update(md4.digest(), 0, 16);
            System.arraycopy(md4temp.digest(), 0, edonkeyHash, 0, 16);
        }
        return AbstractChecksum.format(edonkeyHash, uppercase);
    }
}
