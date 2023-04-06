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
 * Created on 03.08.05
 *
 * @version 	02 (1.09,1.05)
 * @author 		epoximator
 */
package epox.util;

import java.util.ArrayList;
import java.util.StringTokenizer;

import epox.webaom.Options;

public class DSData {
    public String src, dst;
    public Boolean sel;

    public DSData(String s, String d, boolean b) {
        src = s;
        dst = d;
        sel = Boolean.valueOf(b);
    }

    @Override
    public String toString() {
        String d = dst;

        if ("".equals(d)) {
            d = "\\0";
        }

        if (sel.booleanValue()) {
            return src + Options.S_SEP + d;
        }
        return "#" + src + Options.S_SEP + d;

    }

    public static DSData parse(String s0, String s1) {
        boolean b = s0.startsWith("#");

        if (b) {
            s0 = s0.substring(1);
        }

        if ("\\0".equals(s1)) {
            s1 = "";
        }
        return new DSData(s0, s1, !b);
    }

    public static String encode(ArrayList<DSData> mVill) {
        StringBuilder s = new StringBuilder();

        for (DSData ds : mVill) {

            if (!"".equals(ds.src)) {
                s.append(ds).append(Options.S_SEP);
            }
        }
        return s.toString();
    }

    public static String decode(ArrayList<DSData> mVill, String s) {
        mVill.clear();
        StringTokenizer st = new StringTokenizer(s, Options.S_SEP);

        while (st.hasMoreTokens()) {
            mVill.add(DSData.parse(st.nextToken(), st.nextToken()));
        }
        return s;
    }
}
