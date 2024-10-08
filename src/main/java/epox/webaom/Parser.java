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
 * Created on 22.01.05
 *
 * @version 	0.01
 * @author 		epoximator
 */
package epox.webaom;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.Writer;

import javax.swing.JFileChooser;

import epox.util.U;
import epox.webaom.data.AFile;
import epox.webaom.data.Anime;
import epox.webaom.data.Base;
import epox.webaom.data.Ep;
import epox.webaom.data.Group;

public class Parser {
    public static Group parseGroup(String s[]) {
        if (s == null) {
            return null;
        }

        Group g = new Group(Integer.parseInt(s[0]));
        g.name = s[5];
        g.sname = s[6];

        return g;
    }

    public static Ep parseEpisode(String s[]) {
        if (s == null) {
            return null;
        }

        Ep e = new Ep(Integer.parseInt(s[0]));
        e.num = s[5];
        e.eng = s[6];
        e.rom = s[7];
        e.kan = s[8];

        return e;
    }

    public static Anime parseAnime(String s[]) {
        if (s == null) {
            return null;
        }

        Anime a = new Anime(Integer.parseInt(s[0]));
        a.eps = Integer.parseInt(s[1]);
        a.lep = Integer.parseInt(s[2]);
        a.yea = Integer.parseInt(s[10].substring(0, 4));
        a.yen = s[10].length() != 9 ? a.yea : Integer.parseInt(s[10].substring(5, 9));
        a.typ = s[11].intern();
        a.rom = s[12];
        a.kan = s[13];
        a.eng = s[14];
        a.cat = s[18];

        return a;
    }

    private static final String n[] = { "", "0", "00", "000", "0000" };

    public static String pad(String s, int tot) {
        int total = tot;
        int x = s.indexOf('-');
        int y = s.indexOf(',');
        char c = '-';

        if (y >= 0) {
            if (x < 0 || (y < x && x >= 0)) {
                c = ',';
                x = y;
            }
        }

        String num = s;
        if (x >= 0) {
            num = s.substring(0, x);
        }

        if (total == 0) {
            total = A.ASNO; // presume this
        }

        int nr;
        StringBuilder pre = new StringBuilder();
        char a = num.charAt(0);
        if (Character.isDigit(a)) {
            nr = U.i(num);
        } else {
            nr = U.i(num.substring(1));
            pre.append(a);
            // !tot = nr; //no total specials
            total = A.ASSP;
        }

        if (total < nr) {
            total = nr; // just in case...
        }

        String sp = pre.append(Parser.n[Parser.log10(total) - Parser.log10(nr > 0 ? nr : 1)]).append(nr).toString();
        if (x >= 0) {
            // return sp+c+pad(s.substring(x+1), tot);
            return sp + c + s.substring(x + 1);
        }

        return sp;
    }

    private static int log10(int i) {
        return (int) (Math.log(i) / Math.log(10));
    }

    public static void exportDB() {
        if (A.p != null) {
            try {
                synchronized (A.p) {
                    JFileChooser fc = new JFileChooser();

                    if (A.dir != null) {
                        fc.setCurrentDirectory(new File(A.dir));
                    }

                    if (fc.showDialog(A.component, "Select File") == JFileChooser.APPROVE_OPTION) {
                        File file = fc.getSelectedFile();
                        A.dir = file.getParentFile().getAbsolutePath();
                        try (Writer fw = new OutputStreamWriter(new FileOutputStream(file), "UTF-8")) {
                            fw.write("a0\r\n");
                            A.p.mkArray();

                            for (int i = 0; i < A.p.size(); i++) {
                                Base p0 = A.p.get(i);
                                p0.mkArray();
                                fw.write("a" + p0.serialize() + A.S_N);

                                for (int j = 0; j < p0.size(); j++) {
                                    Base p1 = p0.get(j);
                                    p1.mkArray();
                                    fw.write("e" + p1.serialize() + A.S_N);

                                    for (int k = 0; k < p1.size(); k++) {
                                        AFile f = (AFile) p1.get(k);
                                        fw.write("f" + f.serialize() + A.S_N);

                                        if (f.getJob() != null) {
                                            fw.write("j" + f.getJob().serialize() + A.S_N);
                                        }
                                    }

                                }
                            }
                            fw.flush();
                        }
                    }
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    public static void importDB() throws Exception {
        A.db.debug = false;

        if (A.p != null) {
            try {
                synchronized (A.p) {
                    JFileChooser fc = new JFileChooser();

                    if (A.dir != null) {
                        fc.setCurrentDirectory(new File(A.dir));
                    }

                    if (fc.showDialog(A.component, "Select File") == JFileChooser.APPROVE_OPTION) {
                        File file = fc.getSelectedFile();
                        A.dir = file.getParentFile().getAbsolutePath();
                        try (BufferedReader br = new BufferedReader(
                                new InputStreamReader(new FileInputStream(file), "UTF-8"))) {
                            String v = br.readLine();
                            boolean froms = false;

                            if ("s0".equals(v)) {
                                froms = true;
                            } else if (!"a0".equals(v)) {
                                br.close();
                                throw new Exception("format not supported");
                            }
                            // A.p.mkArray();
                            String line;
                            Anime a = null;
                            Ep e = null;
                            AFile f = null;
                            Job j = null;

                            while (br.ready()) {
                                line = U.htmldesc(br.readLine());

                                if (line.length() < 1) {
                                    continue;
                                }

                                switch (line.charAt(0)) {
                                case 'a':
                                    a = new Anime(U.split(line.substring(1), '|'));
                                    A.cache.add(a, 2, DB.I_A);
                                    A.p.add(a);
                                    break;
                                case 'e':
                                    e = new Ep(U.split(line.substring(1), '|'));
                                    A.cache.add(e, 2, DB.I_E);
                                    break;
                                case 'f':
                                    if (a != null && e != null) {
                                        String s[] = U.split(line.substring(1), '|');
                                        f = new AFile(s);
                                        Group g = new Group(f.gid);
                                        g.name = s[20];
                                        g.sname = s[21];
                                        A.cache.add(g, 1, DB.I_G);
                                        f.anime = a;
                                        f.ep = e;
                                        f.group = g;
                                        f.def = a.rom + " - " + e.num + " - " + e.eng + " - ["
                                                + ((f.gid > 0) ? g.sname : "RAW") + "]";
                                        A.db.update(f.fid, f, DB.I_F);
                                    }
                                    break;
                                case 'j':
                                    if (f != null) {
                                        line = line.substring(1);
                                        if (froms) {
                                            j = new Job(new File(File.separatorChar + U.replace(line, "/", "")),
                                                    Job.FINISHED);
                                            j.mSo = line;
                                            j._ed2 = f.ed2;
                                            j.mLs = f.mLs;
                                        } else {
                                            j = new Job(U.split(line, '|'));
                                        }
                                        j.m_fa = f;
                                        f.setJob(j);
                                        A.jobs.add(j);
                                        A.db.update(0, j, DB.I_J);
                                    }
                                    break;
                                default:
                                    break;
                                }
                            }
                        }
                    }
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        A.db.debug = true;
    }
}
