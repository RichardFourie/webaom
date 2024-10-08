/******************************************************************************
 *
 * Jacksum version 1.5.0 - checksum utility in Java
 * Copyright (C) 2001-2004 Dipl.-Inf. (FH) Johann Nepomuk Loefflmann,
 * All Rights Reserved, http://www.jonelo.de
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 * E-mail: jonelo@jonelo.de
 *
 *****************************************************************************/

package jonelo.jacksum.algorithm;

import java.util.zip.Checksum;

abstract public class AbstractChecksum implements Checksum {
    protected long value;
    protected long length;
    protected boolean uppercase;

    public AbstractChecksum() {
        value = 0;
        length = 0;
        uppercase = false;
    }

    @Override
    public void reset() {
        value = 0;
        length = 0;
    }

    @Override
    public void update(byte[] bytes, int offset, int len) {

        for (int i = offset; i < len; i++) {
            update(bytes[i]);
        }
    }

    public void update(byte b) {
        update(b & 0xFF);
    }

    @Override
    public void update(int b) {
        length++;
    }

    @Override
    public void update(byte[] bytes) {
        update(bytes, 0, bytes.length);
    }

    @Override
    public long getValue() {
        return value;
    }

    public String getHexValue() {
        String s = Long.toHexString(getValue());
        return (uppercase ? s.toUpperCase() : s);
    }

    private final static char[] HEX = "0123456789abcdef".toCharArray();

    public static String hexformat(long value, int nibbles) {
        StringBuilder sb = new StringBuilder(Long.toHexString(value));

        while (sb.length() < nibbles) {
            sb.insert(0, '0');
        }
        return sb.toString();
    }

    public static String format(byte[] bytes, boolean uppercase) {

        if (bytes == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        int b;

        for (byte element : bytes) {
            b = element & 0xFF;
            sb.append(AbstractChecksum.HEX[b >>> 4]);
            sb.append(AbstractChecksum.HEX[b & 0x0F]);
        }
        return (uppercase ? sb.toString().toUpperCase() : sb.toString());
    }
}
