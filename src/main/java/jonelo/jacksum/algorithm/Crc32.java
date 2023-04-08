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

package jonelo.jacksum.algorithm;

import java.util.zip.CRC32;

/*
  A class that can be used to compute the CRC32 of a data stream.
  This implementation uses the class java.util.zip.CRC32 from the Java Standard API.
 */

public class Crc32 extends AbstractChecksum {

    private final CRC32 crc32;

    public Crc32() {
        crc32 = new CRC32();
    }

    @Override
    public void reset() {
        crc32.reset();
        length = 0;
    }

    @Override
    public void update(byte[] buffer, int offset, int len) {
        crc32.update(buffer, offset, len);
        length += len;
    }

    @Override
    public void update(int integer) {
        crc32.update(integer);
        length++;
    }

    @Override
    public long getValue() {
        return crc32.getValue();
    }

    @Override
    public String getHexValue() {
        String s = AbstractChecksum.hexformat(getValue(), 8);
        return (uppercase ? s.toUpperCase() : s);
    }
}
