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
 * @version 	03
 * @author 		epoximator
 */
package epox.webaom.data;

import epox.util.U;
import epox.webaom.A;
import epox.webaom.Job;

public class AFile extends Base {
    public int fid, aid, eid, gid, lid, stt, len;
    public String ed2, md5, sha, crc, dub, sub, qua, rip, res, vid, aud, def, ext;

    public Ep ep;
    public AG ag;
    public Group group;
    public Anime anime;
    private Job job = null;

    public AFile(int id) {
        fid = id;
        ext = null;
    }

    public AFile(String s[]) {
        int i = 0;
        fid = U.i(s[i++]);
        aid = U.i(s[i++]);
        eid = U.i(s[i++]);

        if (s[i].length() < 1) {
            gid = 0;
        } else {
            gid = U.i(s[i]);
        }
        i++;
        lid = U.i(s[i++]);
        stt = U.i(s[i++]);

        if (s[i].length() < 1) {
            mLs = 0;
        } else {
            mLs = Long.parseLong(s[i]);
        }
        i++;
        ed2 = s[i++];
        md5 = U.n(s[i++]);
        sha = U.n(s[i++]);
        crc = U.n(s[i++]);

        dub = s[i++].intern();
        sub = s[i++].intern();
        qua = s[i++].intern();
        rip = s[i++].intern();
        aud = s[i++].intern();
        vid = s[i++].intern();
        res = s[i++].intern();
        ext = s[i++].intern();
        len = U.i(s[i++]);
    }

    public Job getJob() {
        return job;
    }

    public void setJob(Job j) {
        job = j;
        // mBs = job.getFile().exists();
        // if(mBs)
        // mLs = job.getFile().length();
    }

    @Override
    public String toString() {
        if (job != null) {
            return job.getFile().getName();
        }

        return def;
    }

    /*
     * public String toString(){ return
     * ed2+md5+sha+crc+dub+sub+qua+rip+res+vid+aud+def+ep; }
     */
    @Override
    public String serialize() {
        return "" + fid + Base.S + aid + Base.S + eid + Base.S + gid + Base.S + lid + Base.S + stt + Base.S + mLs
                + Base.S + ed2 + Base.S + md5 + Base.S + sha + Base.S + crc + Base.S + dub + Base.S + sub + Base.S + qua
                + Base.S + rip + Base.S + aud + Base.S + vid + Base.S + res + Base.S + ext + Base.S + len + Base.S
                + (group != null ? group.serialize() : "");
    }

    public static Base getInst(String[] s) {
        return new AFile(s);
    }

    @Override
    public Object getKey() {
        return Integer.valueOf(fid);
    }

    @Override
    public void clear() {
        //
    }

    public void pack() {
        dub = dub.replace('/', '&'); // for jap/eng
        vid = vid.replace('/', ' '); // for 'H264/AVC'
        int i = vid.indexOf(" ");

        if (i > 0) {
            vid = vid.substring(0, i);
        }
        i = aud.indexOf(" ("); // for Vorbis (Ogg Vorbis)

        if (i > 0) {
            aud = aud.substring(0, i);
        }

        if (dub.startsWith("dual (")) { // remove dual()
            dub = dub.substring(6, dub.lastIndexOf(')'));
        }

        vid = vid.intern();
        aud = aud.intern();
        dub = dub.intern();
    }

    private static String url0(String str, boolean non) {
        if (non) {
            return "http://" + A.S_WEB + "/perl-bin/animedb.pl?" + str + "&nonav=1";
        }

        return "http://" + A.S_WEB + "/perl-bin/animedb.pl?" + str;
    }

    private static String url1(String str) {
        return AFile.url0("show=" + str, true);
    }

    public String urlAnime() {
        return AFile.url1("anime&aid=" + aid);
    }

    public String urlExport() {
        return AFile.url1("ed2kexport&h=1&aid=" + aid);
    }

    public String urlEp() {
        return AFile.url1("ep&aid=" + aid + "&eid=" + eid);
    }

    public String urlFile() {
        return AFile.url1("file&aid=" + aid + "&eid=" + eid + "&fid=" + fid);
    }

    public String urlGroup() {
        return AFile.url1("group&gid=" + gid);
    }

    public String urlMylistE(int i) {
        if (i < 2) {
            return urlMylist();
        }

        return AFile.url1("mylist&do=add&aid=" + aid + "&eid=" + eid + "&fid=" + fid + "&lid=" + i);
    }

    public String urlMylist() {
        try {
            return AFile.url1("mylist&expand=" + aid + "&char=" + anime.rom.charAt(0) + "#a" + aid);
        } catch (@SuppressWarnings("unused") Exception e) {
            return AFile.url1("mylist");
        }
    }

    public String urlYear() {
        try {
            return AFile.url0("do.search=%20Start%20Search%20&show=search&noalias=1&search.anime.year=" + anime.yea,
                    false);
        } catch (@SuppressWarnings("unused") Exception e) {
            return AFile.url1("search");
        }
    }

    public static final int F_CRCOK = 1, F_CRCERR = 2, F_ISV2 = 4, F_ISV3 = 8, F_ISV4 = 16, F_ISV5 = 32, F_UNC = 64,
            F_CEN = 128;

    ///
    public boolean inYear(String s) {
        s.replace(" ", "");
        int i = s.indexOf('-');

        if (i > 0) { // Range
            int start = Integer.parseInt(s.substring(0, i));
            int end = Integer.parseInt(s.substring(i + 1));

            if (start > end) {
                int t = end;
                end = start;
                start = t;
            }

            return anime.yea >= start && anime.yea <= end;
        }

        return anime.yea == Integer.parseInt(s);
    }

    /*
     * f_state 0 - crc ok 1 - corrupt 2 - v2 3 4 5 - v5 6 - uncensored 7 - censored
     */
    public String getVersion() {
        return switch (stt & 0x3C) {
        case F_ISV2 -> "v2";
        case F_ISV3 -> "v3";
        case F_ISV4 -> "v4";
        case F_ISV5 -> "v5";
        default -> "";
        };
    }

    public String getCensored() {
        return switch (stt & 0xC0) {
        case F_CEN -> "cen";
        case F_UNC -> "unc";
        default -> "";
        };
    }

    public String getInvalid() {
        if ((stt & AFile.F_CRCERR) == AFile.F_CRCERR) {
            return "invalid crc";
        }

        return "";
    }

    public String mds() {
        if (anime == null || ep == null) {
            return "N/A";
        }
        StringBuilder x = new StringBuilder();

        if (crc == null || crc.length() < 1) {
            x.append('c');
        }

        if (md5 == null || md5.length() < 1 || sha == null || sha.length() < 1) {
            x.append('h');
        }

        if (len < 1) {
            x.append('l');
        }

        if (dub.indexOf("unknown") >= 0) {
            x.append('d');
        }

        if (sub.indexOf("unknown") >= 0) {
            x.append('s');
        }

        if (aud.indexOf("unknown") >= 0) {
            x.append('a');
        }

        if (vid.indexOf("unknown") >= 0) {
            x.append('v');
        }

        if ("0x0".equals(res) || "unknown".equals(res)) {
            x.append('x');
        }

        return x.toString();
    }

    public String mda() {
        if (anime == null || ep == null) {
            return "N/A";
        }
        StringBuilder x = new StringBuilder();

        if (qua.indexOf("unknown") >= 0) {
            x.append('q');
        }

        if (rip.indexOf("unknown") >= 0) {
            x.append('o');
        }

        if (ep.eng == null || ep.eng.length() < 1) {
            x.append('e');
        }

        if (ep.kan == null || ep.kan.length() < 1) {
            x.append('k');
        }

        if (ep.rom == null || ep.rom.length() < 1) {
            x.append('r');
        }

        return x.toString();
    }
    /*
     * public int compareTo(Object o){ if(o instanceof AFile){ AFile f = (AFile)o;
     * if(mBs==f.mBs){ return job.getFile().compareTo(f.job.getFile()); }
     * if(mBs&&!f.mBs) return -1; return 1; } return super.compareTo(o); }
     */
}
