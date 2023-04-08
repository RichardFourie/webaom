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
 * Created on 02.08.05
 *
 * @version 	04 (1.14,1.09)
 * @author 		epoximator
 */
package epox.webaom;

import java.io.File;

import epox.av.FileInfo;
import epox.util.U;
import epox.webaom.data.AFile;
import epox.webaom.data.AMap;

public class Job {
    // Size, int=4, long=1, pointer=4, string=7 -> 4*4+1*8+4*8+7*8= 112 bytes / calc
    // = 108 bytes
    private static final char S = '|';
    private int mIst;
    public int mIdid, mIlid = 0, mIfid = 0;
    public boolean mBf = true; // fresh
    public long mLs;
    public File m_fc, m_fn;
    public AFile m_fa;
    public FileInfo m_fi;
    public String mSo, mSe, _ed2, _md5, _sha, _tth, _crc;

    public String serialize() {
        return "" + getStatus() + Job.S + m_fc + Job.S + mLs + Job.S + _ed2 + Job.S + _md5 + Job.S + _sha + Job.S + _tth
                + Job.S + _crc + Job.S + mSo;
    }

    public Job(String[] s) {
        this(new File(s[1]), U.i(s[0]));
        int i = 2;
        mLs = Long.parseLong(s[i++]);
        _ed2 = s[i++];
        _md5 = U.n(s[i++]);
        _sha = U.n(s[i++]);
        _tth = U.n(s[i++]);
        _crc = U.n(s[i++]);
        mSo = s[i++];
    }

    public Job(File f, int status) {
        mIst = status;
        m_fc = f;
        m_fn = null;
        m_fa = null;
        _ed2 = _md5 = _sha = _tth = _crc = null;

        mLs = f.length();
        mSo = f.getName();

        if (!m_fc.exists()) {
            mIst |= Job.H_MISSING;
        } else {
            mIst |= Job.H_PAUSED;
        }
        A.jobc.register(-1, -1, mIst & Job.M_R, getHealth());
    }

    @Override
    public String toString() {
        return m_fc.getName() + ": " + getStatusText();
    }

    public boolean hide(String s) {
        if (s == null || s.length() < 1) {
            return false;
        }

        if (s.charAt(0) == '!') {
            return m_fc.getAbsolutePath().matches(s.substring(1));
        }

        return !m_fc.getAbsolutePath().matches(s);
    }

    /*
     * public String toString(){ return mSo+mSe+_ed2+_md5+_sha+_tth+_crc+m_fc+m_fa;
     * }
     */
    public File getFile() {
        return m_fc;
    }

    public String getExtension() {
        if (m_fa == null || m_fa.ext == null) {
            String s = m_fc.getName();
            int i = s.lastIndexOf('.');

            if (i < 1) {
                System.out.println("No ext: " + s);

                return "unk";
            }

            return s.substring(i + 1);
        }

        return m_fa.ext;
    }

    public int getStatus() {
        return mIst & Job.M_S;
    }

    public int getHealth() {
        return mIst & Job.M_H;
    }

    public boolean check(int s) {
        return (mIst & s) == s;
    }

    public boolean checkOr(int s) {
        return (mIst & s) > 0;
    }

    public boolean checkSep(int s, int f, boolean u) {
        // System.err.println(Integer.toHexString(mIst&Job.M_SS)+"
        // "+Integer.toHexString(s&Job.M_SS));
        boolean b = (mIst & Job.M_SS & s) > 0 && (mIst & Job.M_H & s) > 0
                && ((s & Job.M_D) < 1 || (mIst & Job.M_D & s) > 0);

        if (u) {
            return m_fa == null && b;
        }

        return b && (f < 1 || (m_fa != null && (m_fa.stt & f) > 0));
    }

    public boolean isLocked(int s) {
        int h = getHealth();

        if (h < Job.H_MISSING) {
            return false;
        }

        if (h == Job.H_MISSING) {
            switch (s) {
            case FINISHED:
            case ADDWAIT:
            case REMWAIT:
                return false;
            default:
                break;
            }
        }

        return true;
    }

    public boolean isCorrupt() {
        return m_fa != null && ((m_fa.stt & AFile.F_CRCERR) == AFile.F_CRCERR);
    }

    public boolean incompl() {
        return m_fa == null || m_fa.anime == null || m_fa.ep == null;
    }

    public String getStatusText() {
        if (check(Job.H_NORMAL)) {
            return Job.statusStr(getStatus());
        }

        return Job.statusStr(getStatus()) + " [" + Job.statusStr(getHealth()) + "]";
    }

    public void setStatus(int status, boolean test) {
        int health = getHealth();

        if (test) {
            // if(health>H_PAUSED&&!(status==FINISHED||status==REMWAIT||status==ADDWAIT))
            // &&(status&F_PD)==0)//extra check, could be removed maybe
            // return;
            if (isLocked(status)) {
                return;
            }

            if (health == Job.H_PAUSED || health == Job.H_MISSING) {
                setHealth(Job.H_NORMAL);
            }
            health = getHealth();
        }

        if ((status & Job.F_DB) == Job.F_DB) {// only for main status
            if (test && health == Job.H_NORMAL) {
                A.jobs.updateQueues(this, getStatus(), status & Job.M_S);
            }
            // A.jobc.register(getRegVal(), (status|H_NORMAL)&M_R);
            health = Job.H_NORMAL;

            if (status == Job.FINISHED && !m_fc.exists()) {
                health = Job.H_MISSING;
            }
            A.jobc.register(mIst & Job.M_R, getHealth(), status & Job.M_R, health);
            mIst = status | health;

        } else { // only for main status
            mIst = status | Job.H_NORMAL;
            // if(m_fc.exists())
            // mIh = NORMAL;
            // else mIh = MISSING;
        }
    }

    private void setHealth(int health) {
        int s = getStatus();

        if (!check(Job.H_NORMAL) && health == Job.H_NORMAL) {
            A.jobs.updateQueues(this, 0, s);
        } else if (check(Job.H_NORMAL) && health != Job.H_NORMAL) {
            A.jobs.updateQueues(this, s, -1);
        }

        // A.jobc.register(getRegVal(), s|health);
        A.jobc.register(mIst & Job.M_R, getHealth(), mIst & Job.M_R, health);
        setHealth0(health);
    }

    public void setHealth0(int health) {
        mIst = (mIst & Job.M_S) | health;
    }

    public void setError(String str) {
        mSe = str;
    }

    public void updateHealth(int i) {
        if (i != Job.H_DELETED && checkOr(Job.H_MISSING | Job.H_DELETED)) {
            return;
        }
        int health = getHealth();

        switch (i) {
        case H_PAUSED:
            if (health == Job.H_NORMAL) {
                health = Job.H_PAUSED;// turn pause on
            } else if (health == Job.H_PAUSED) {
                health = Job.H_NORMAL; // turn pause off
            }
            break;
        case H_DELETED:
            if (health == Job.H_DELETED) {
                health = (m_fc.exists() ? Job.H_NORMAL : Job.H_MISSING);
                A.db.update(0, this, DB.I_J);
            } else {
                health = Job.H_DELETED; // delete
                A.db.removeJob(this);
            }
            break;
        case H_MISSING:
            health = Job.H_MISSING;
            break;
        default:
            break;
        }
        setHealth(health);
    }

    public void find(File f) {
        if (!check(Job.H_MISSING)) {
            return;
        }
        JobMan.setJobFile(this, f);
        setHealth0(f.exists() ? Job.H_PAUSED : Job.H_MISSING);
        mIdid = -1;
    }

    /// STATIC
    public static final int S_DONE = 0x00000001, // status
            S_DO = 0x00000002, S_DOING = 0x00000014, S_FAILED = 0x00000008, U_2 = 0x00000020, // sub status
            H_NORMAL = 0x00000100, // health
            H_PAUSED = 0x00000200, H_MISSING = 0x00000400, H_DELETED = 0x00000800, D_DIO = 0x00010000, // mode
            D_NIO = 0x00020000,
//	M_USR		= 0x00040000,
            T_1 = 0x00100000, // type
            T_2 = 0x00200000, T_4 = 0x00400000,
//	T_8			= 0x00800000,
            F_DB = 0x01000000, // flag
            F_UNK = 0x02000000, F_PD = 0x00000000, // pardoned
            M_H = 0x0000ff00, // mask
            M_S = 0x0fff00ff, M_SS = 0x0000001f, M_D = 0x000f0000, M_R = 0x0f0f001f;

    public static final int FAILED = Job.S_FAILED | Job.F_DB, // 0x00,0 -> 16777224
            UNKNOWN = Job.S_DONE | Job.F_UNK | Job.F_DB, // 0x10,16 -> 50331649
            FINISHED = Job.S_DONE | Job.F_DB | Job.F_PD, // 0xf0,240 -> 16777217

            HASHWAIT = Job.D_DIO | Job.T_1 | Job.S_DO | Job.F_DB, // 0x30,48 -> 17891330
            HASHING = Job.D_DIO | Job.T_1 | Job.S_DOING, // 0x32,
            HASHED = Job.D_DIO | Job.T_1 | Job.S_DONE, // 0x3f,

            IDENTWAIT = Job.D_NIO | Job.T_1 | Job.S_DO | Job.F_DB, // 0x50,80 -> 17956866
            IDENTIFYING = Job.D_NIO | Job.T_1 | Job.S_DOING, // 0x52,
            IDENTIFIED = Job.D_NIO | Job.T_1 | Job.S_DONE, // 0x5f,

            ADDWAIT = Job.D_NIO | Job.T_2 | Job.S_DO | Job.F_DB | Job.F_PD, // 0x70,112 -> 19005442
            ADDING = Job.D_NIO | Job.T_2 | Job.S_DOING, // 0x72,
            ADDED = Job.D_NIO | Job.T_2 | Job.S_DONE, // 0x7f,

            MOVEWAIT = Job.D_DIO | Job.T_2 | Job.S_DO | Job.F_DB, // 0x90,144 -> 18939906
            MOVING = Job.D_DIO | Job.T_2 | Job.S_DOING, // 0x92,
            MOVECHECK = Job.D_DIO | Job.T_2 | Job.U_2 | Job.S_DOING, // 0x94,
            MOVED = Job.D_DIO | Job.T_2 | Job.S_DONE, // 0x9f,

//	INPUTWAIT	= M_USR|U_1|S_DO|F_DB,	//0xb0,

            REMWAIT = Job.D_NIO | Job.T_4 | Job.S_DO | Job.F_DB | Job.F_PD, // 0xc0,
            REMING = Job.D_NIO | Job.T_4 | Job.S_DOING, // 0xc2,

            PARSEWAIT = Job.D_DIO | Job.T_4 | Job.S_DO | Job.F_DB | Job.F_PD, // 0xd0,
            PARSING = Job.D_DIO | Job.T_4 | Job.S_DOING; // 0xd2,

    private static String statusStr(int i) {
        return switch (i) {
        case HASHWAIT -> "Wait/Hash";
        case HASHING -> "Hashing";
        case HASHED -> "Hashed";
        case IDENTWAIT -> "Wait/ID";
        case IDENTIFYING -> "Identifying";
        case IDENTIFIED -> "Identified";
        case ADDWAIT -> "Wait/Add";
        case ADDING -> "Adding";
        case ADDED -> "Added";
        case MOVEWAIT -> "Wait/Move";
        case MOVING -> "Moving";
        case MOVECHECK -> "Checking";
        case MOVED -> "Moved";
        case FINISHED -> "Finished";
        case UNKNOWN -> "Unknown";
        case FAILED -> "Failed";
        case H_PAUSED -> "P";
        case H_DELETED -> "D";
        case H_MISSING -> "M";
        case REMWAIT -> "Wait/Rem";
        case REMING -> "Removing";
        case PARSEWAIT -> "Wait/Parse";
        case PARSING -> "Parsing";
        default -> "" + i;
        };
    }

    public String convert(String s) {
        String newS = s;
        String avi0 = U.getInTag(newS, "avinfo");

        if (avi0 != null) {
            String avi1 = avi0;

            if (m_fi != null) {
                String[] t = { "vid", "aud", "sub" };

                for (int i = 0; i < 3; i++) {
                    String s0 = U.getInTag(avi1, t[i]);

                    if (s0 == null) {
                        continue;
                    }
                    String s1 = m_fi.convert(s0, i);
                    avi1 = U.replace(avi1, s0, s1);
                }
            } else {
                avi1 = "";
            }
            newS = U.replace(newS, avi0, avi1);
        }

        return U.replaceCCCode(newS, genMap());
    }

    public AMap genMap() {
        AMap am = new AMap();

        am.put("fil", m_fc.getName());
        am.put("pat", m_fc.getParent());
        am.put("new", ((m_fn != null) ? m_fn.toString() : ""));
        am.put("ori", mSo);
        am.put("siz", mLs);
        StringBuilder stat = new StringBuilder().append(getStatusText());

        if (check(Job.FAILED) && mSe != null) {
            stat.append(". ").append(mSe);
        }
        am.put("sta", stat.toString());

        if (m_fa != null) {
            am.put("aid", m_fa.aid);
            am.put("eid", m_fa.eid);
            am.put("fid", m_fa.fid);
            am.put("gid", m_fa.gid);
            am.put("lid", mIlid);
            am.put("ver", m_fa.getVersion());
            am.put("ula", m_fa.urlAnime());
            am.put("ule", m_fa.urlEp());
            am.put("ulf", m_fa.urlFile());
            am.put("ulg", m_fa.urlGroup());
            am.put("ulx", m_fa.urlMylistE(mIlid));
            am.put("ulm", m_fa.urlMylist());
            am.put("uly", m_fa.urlYear());
            am.put("ed2", m_fa.ed2.toLowerCase());
            am.put("ED2", m_fa.ed2.toUpperCase());
            am.put("cen", m_fa.getCensored());
            am.put("inv", m_fa.getInvalid());
            am.put("dub", m_fa.dub);
            am.put("sub", m_fa.sub);
            am.put("src", m_fa.rip);
            am.put("res", m_fa.res);
            am.put("vid", m_fa.vid);
            am.put("aud", m_fa.aud);
            am.put("qua", m_fa.qua);

            if (m_fa.sha != null) {
                am.put("sha", m_fa.sha.toLowerCase());
                am.put("SHA", m_fa.sha.toUpperCase());
            }

            if (m_fa.md5 != null) {
                am.put("md5", m_fa.md5.toLowerCase());
                am.put("MD5", m_fa.md5.toUpperCase());
            }

            if (m_fa.crc != null) {
                am.put("CRC", m_fa.crc.toUpperCase());
                am.put("crc", m_fa.crc.toLowerCase());
            }

            if (m_fa.anime != null) {
                am.put("ann", m_fa.anime.rom);
                am.put("kan", m_fa.anime.kan);
                am.put("eng", m_fa.anime.eng);
                am.put("eps", m_fa.anime.eps);
                am.put("typ", m_fa.anime.typ);
                am.put("yea", m_fa.anime.yea);
                am.put("gen", m_fa.anime.cat.replace(",", ", "));
                am.put("lep", m_fa.anime.lep);
                am.put("yen", m_fa.anime.yen); // NvrBst: Unsure about this change; Needs Testing
            }

            if (m_fa.ep != null) {
                am.put("epn", m_fa.ep.eng);
                am.put("epk", m_fa.ep.kan);
                am.put("epr", m_fa.ep.rom);
            }

            if (m_fa.anime != null && m_fa.ep != null) {
                am.put("enr", Parser.pad(m_fa.ep.num, m_fa.anime.getTotal()));
            }

            if (m_fa.group != null && m_fa.gid > 0) {
                am.put("grp", m_fa.group.sname);
                am.put("grn", m_fa.group.name);
            } else {
                am.put("grp", "unknown");
                am.put("grn", "unknown");
            }
        } else if (_ed2 != null) {
            am.put("ed2", _ed2.toLowerCase());
            am.put("ED2", _ed2.toUpperCase());
        }
        return am;
    }
}
