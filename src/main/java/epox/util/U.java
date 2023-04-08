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
 * Created on 25.feb.2006 18:58:58
 * Filename: U.java
 */
package epox.util;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.text.DateFormat;
import java.text.DecimalFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Locale;

/**
 * Utility class.
 *
 * @author JV
 * @version X
 */
public class U {
    private static final DateFormat daf = DateFormat.getTimeInstance(DateFormat.MEDIUM, Locale.GERMANY);
    private static final DecimalFormat def = new DecimalFormat("0.00");

    public static String time() {
        return U.daf.format(new Date(System.currentTimeMillis()));
    }

    public static void err(Object o) {
        System.err.println("! " + o);
    }

    public static void out(Object o) {
        System.out.println(o);
    }

    public static boolean alfanum(String str) {
        return str.matches("^[a-zA-Z0-9\\-\\_]{3,16}$");
    }

    public static String replace(String str, String src, String dst) {
        String newStr = str == null ? "" : str;
        int ls = src.length();
        int ld = dst.length();
        int i = newStr.indexOf(src);

        while (i >= 0) {
            newStr = newStr.substring(0, i) + dst + newStr.substring(i + ls);
            i = newStr.indexOf(src, i + ld);
        }

        return newStr;
    }

    public static String getInTag(String str, String tag) {
        int x = str.indexOf("<" + tag + ">");

        if (x < 0) {
            return null;
        }
        x += tag.length() + 2;
        int y = str.indexOf("</" + tag + ">", x);

        if (y < 0) {
            return null;
        }
        return str.substring(x, y);
    }

    public static int i(String s) throws NumberFormatException {
        return Integer.parseInt(s);
    }

    public static String n(String str) {

        if (str == null || str.length() < 1 || "null".equals(str)) {
            return null;
        }
        return str;
    }

    public static String[] split(String sb, char c) { // includes empty strings (vs String.split())
        int cnt = 1;

        // StringBuffer sb = new StringBuffer(src);
        for (int i = 0; i < sb.length(); i++) {

            if (sb.charAt(i) == c) {
                cnt++;
            }
        }

        if (cnt < 2) {
            return new String[] { sb };
        }
        int pos[] = new int[cnt];
        int j = 0;

        for (int i = 0; i < sb.length(); i++) {

            if (sb.charAt(i) == c) {
                pos[j++] = i;
            }
        }
        pos[cnt - 1] = sb.length();
        String res[] = new String[cnt];
        j = 0;

        for (int i = 0; i < cnt; i++) {
            res[i] = sb.substring(j, pos[i]);
            j = pos[i] + 1;
        }
        return res;
    }

    public static String dehtmlize(String htm) {

        if (htm == null) {
            return null;
        }
        StringBuilder sb0 = new StringBuilder(htm.length());
        StringBuilder sb1 = new StringBuilder(htm);
        boolean in = false;
        char c;

        for (int i = 0; i < sb1.length(); i++) {
            c = sb1.charAt(i);

            if (c == '<') {
                in = true;
                continue;
            }

            if (c == '>') {
                in = false;
                continue;
            }

            if (!in) {
                sb0.append(c);
            }
        }
        return sb0.toString();
    }

    public static String htmldesc(String s) {

        if (s == null) {
            return null;
        }
        StringBuilder sb0 = new StringBuilder(s);
        StringBuilder sb1 = new StringBuilder(s.length());
        StringBuilder sb2 = new StringBuilder(5);
        char c;
        boolean ok = false;
        int len = sb0.length();

        for (int i = 0; i < len; i++) {
            c = sb0.charAt(i);

            if (c == '&' && i < (len - 2)) {

                if (sb0.charAt(i + 1) == '#') {
                    ok = true;
                    i++;
                    sb2.delete(0, sb2.length());
                } else {
                    sb1.append(c);
                }
            } else if (c == ';') {

                if (ok) {

                    try {
                        sb1.append((char) Integer.parseInt(sb2.toString()));
                    } catch (NumberFormatException e) {
                        sb1.append('&');
                        sb1.append('#');
                        sb1.append(sb2);
                        sb1.append(c);
                    }
                    ok = false;
                } else {
                    sb1.append(';');
                }
            } else if (ok) {

                if (Character.isDigit(c) && sb2.length() < 11) {
                    sb2.append(c);
                } else {
                    ok = false;
                    sb1.append('&');
                    sb1.append('#');
                    sb1.append(sb2);
                    sb1.append(c);
                }
            } else {
                sb1.append(c);
            }
        }
        return sb1.toString();
    }

    private static final char[] S = { ' ', 'K', 'M', 'G', 'T', 'P', 'E' };

    private static String sbyte(double d, int p) {

        if (d < 1000) {
            return U.def.format(d) + " " + U.S[p] + "B";
        }
        return U.sbyte(d / 1024, p + 1);
    }

    public static String sbyte(long l) {
        return U.sbyte(l, 0);
        /*
         * if(l<1000) return def.format(l)+" B";//1024 if(l<1024000) return
         * def.format(l/1024)+" KB";//1048576 if(l<1048576000) return
         * def.format(l/1048576)+" MB";//1073741824 if(l<1073741824000l) return
         * def.format(l/1073741824)+" GB"; return def.format(l/1099511627776l)+" TB";
         */
    }

    public static String fileToString(String path) throws FileNotFoundException, IOException {
        File f = new File(path);

        if (!f.exists() || f.length() > 1024 * 1024) {
            return null;
        }

        try (BufferedInputStream bis = new BufferedInputStream(new FileInputStream(f), (int) f.length())) {
            byte buf[] = new byte[(int) f.length()];
            bis.read(buf);
            return new String(buf);
        }
    }

    public static String replaceCCCode(String s, HashMap<String, ?> m) {
        StringBuilder sb = new StringBuilder(s.length() * 4);
        char c;
        Object o;
        int i;

        for (i = 0; i < s.length() - 3; i++) {
            c = s.charAt(i);

            if (c == '%') {
                o = m.get(s.substring(i + 1, i + 4));

                if (o != null) {
                    sb.append(o);
                    i += 3;
                    continue;
                }
            }
            sb.append(c);
        }

        for (; i < s.length(); i++) {
            sb.append(s.charAt(i));
        }
        return sb.toString();
    }
}
