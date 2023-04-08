// Copyright (C) 2005-2006 epoximator
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

/*
 * Created on 03.10.05
 *
 * @version 	01
 * @author 		epoximator
 */
package epox.webaom.data;

import epox.util.U;

public class Ep extends Base {
    public String num, rom, kan, eng;

    public Ep(int id) {
        this.id = id;
    }

    public Ep(String[] s) {
        int i = 0;
        id = U.i(s[i++]);
        num = s[i++].intern();
        eng = s[i++];
        rom = U.n(s[i++]);
        kan = U.n(s[i++]);
    }

    public static int TPRI = 0;

    @Override
    public String toString() {
        return switch (Ep.TPRI) {
        case 1 -> num + " - " + (rom == null ? eng : rom);
        case 2 -> num + " - " + (kan == null ? eng : kan);
        default -> num + " - " + eng;
        };
    }

    /*
     * public String toString(){ return num+eng+kan+rom; }
     */
    @Override
    public String serialize() {
        return "" + id + Base.S + num + Base.S + eng + Base.S + rom + Base.S + kan;
    }

    @Override
    public int compareTo(Object obj) {
        if (obj instanceof Ep e) {
            /* if(mBs==e.mBs) */try {
                int a = Integer.parseInt(num);
                int b = Integer.parseInt(e.num);
                // if(a==b) return english.compareTo(e.english);
                return a - b;
            } catch (@SuppressWarnings("unused") Exception x) {
                return num.compareTo(((Ep) obj).num);
            }
            /*
             * if(mBs&&!e.mBs) return -1; return 1;
             */
        }

        return super.compareTo(obj);
    }
}
