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
 * Created on 02.09.05
 *
 * @version 	1.09
 * @author 		epoximator
 */
package epox.webaom.ui;

import javax.swing.JTable;
import javax.swing.SwingConstants;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableColumnModel;

import epox.swing.TableModelSortable;
import epox.webaom.Job;
import epox.webaom.JobList;

public class TableModelJobs extends TableModelSortable implements RowModel {
    /**
     *
     */
    private static final long serialVersionUID = -7421586386936926286L;
    public static final int NUMB = 0, LIDN = 1, FIDN = 2, AIDN = 3, EIDN = 4, GIDN = 5, AYEA = 6, AEPS = 7, ALEP = 8,
            FSIZ = 9, FLEN = 10, FILE = 11, PATH = 12, NAME = 13, STAT = 14, AROM = 15, AKAN = 16, AENG = 17, ATYP = 18,
            ENUM = 19, EENG = 20, EKAN = 21, EROM = 22, GNAM = 23, GSHO = 24, FDUB = 25, FSUB = 26, FSRC = 27,
            FQUA = 28, FRES = 29, FVID = 30, FAUD = 31, FMDS = 32, FMDA = 33, AYEN = 34, ccnt = 35, JOB = -1;
    public static long MASK = 1 << TableModelJobs.NUMB | 1 << TableModelJobs.FILE | 1 << TableModelJobs.STAT;

    private static String STRA[];
    static {
        TableModelJobs.STRA = new String[TableModelJobs.ccnt];
        TableModelJobs.STRA[TableModelJobs.NUMB] = "#";
        TableModelJobs.STRA[TableModelJobs.LIDN] = "lid";
        TableModelJobs.STRA[TableModelJobs.FIDN] = "fid";
        TableModelJobs.STRA[TableModelJobs.AIDN] = "aid";
        TableModelJobs.STRA[TableModelJobs.EIDN] = "eid";
        TableModelJobs.STRA[TableModelJobs.GIDN] = "gid";
        TableModelJobs.STRA[TableModelJobs.FSIZ] = "size";
        TableModelJobs.STRA[TableModelJobs.FLEN] = "len";
        TableModelJobs.STRA[TableModelJobs.PATH] = "path";
        TableModelJobs.STRA[TableModelJobs.NAME] = "name";
        TableModelJobs.STRA[TableModelJobs.FILE] = "file";
        TableModelJobs.STRA[TableModelJobs.STAT] = "status";
        TableModelJobs.STRA[TableModelJobs.AKAN] = "kan";
        TableModelJobs.STRA[TableModelJobs.AROM] = "ann";
        TableModelJobs.STRA[TableModelJobs.AENG] = "eng";
        TableModelJobs.STRA[TableModelJobs.AYEA] = "yea";
        TableModelJobs.STRA[TableModelJobs.AYEN] = "yen";
        TableModelJobs.STRA[TableModelJobs.AEPS] = "eps";
        TableModelJobs.STRA[TableModelJobs.ALEP] = "lep";
        TableModelJobs.STRA[TableModelJobs.ATYP] = "typ";
        TableModelJobs.STRA[TableModelJobs.EKAN] = "epk";
        TableModelJobs.STRA[TableModelJobs.EROM] = "epr";
        TableModelJobs.STRA[TableModelJobs.EENG] = "epn";
        TableModelJobs.STRA[TableModelJobs.ENUM] = "enr";
        TableModelJobs.STRA[TableModelJobs.GNAM] = "grn";
        TableModelJobs.STRA[TableModelJobs.GSHO] = "grp";
        TableModelJobs.STRA[TableModelJobs.FDUB] = "dub";
        TableModelJobs.STRA[TableModelJobs.FSUB] = "sub";
        TableModelJobs.STRA[TableModelJobs.FSRC] = "src";
        TableModelJobs.STRA[TableModelJobs.FQUA] = "qua";
        TableModelJobs.STRA[TableModelJobs.FRES] = "res";
        TableModelJobs.STRA[TableModelJobs.FVID] = "vid";
        TableModelJobs.STRA[TableModelJobs.FAUD] = "aud";
        TableModelJobs.STRA[TableModelJobs.FMDS] = "mds";
        TableModelJobs.STRA[TableModelJobs.FMDA] = "mda";
    }
    private JobList jl;
    private int m_current_row;
    private Job m_current_job;

    public TableModelJobs(JobList j) {
        jl = j;
        reset();
    }

    @Override
    public void reset() {
        m_current_row = -1;
        m_current_job = null;
        super.reset();
    }

    @Override
    public int getColumnCount() {
        return TableModelJobs.ccnt;
    }

    @Override
    public Class<?> getColumnClass(int col) {
        if (col == TableModelJobs.FSIZ) {
            return Long.class;
        }

        if (col < TableModelJobs.FILE) {
            return Integer.class;
        }
        return String.class;
    }

    @Override
    public int getRowCount() {
        return jl.size();
    }

    @Override
    public Object getValueAt(int row, int col) {
        int newRow = getRowIndex(row);

        if (col < 1 || newRow != m_current_row) { // if col==0 then it is an update
            m_current_row = newRow;
            m_current_job = jl.get(newRow);
        }
        Job j = m_current_job;

        switch (col) {
        case NUMB:
            return Integer.valueOf(newRow + 1);
        case FSIZ:
            return Long.valueOf(j.mLs);
        case PATH:
            return j.getFile().getParent();
        case NAME:
            return j.getFile().getName();
        case FILE:
            return j.getFile().getAbsolutePath();
        case STAT:
            return j.getStatusText();
        case JOB:
            return j;
        default:
            break;
        }

        if (j.m_fa == null) {
            // return col<FILE?0:"N/A";
            if (col < TableModelJobs.FILE) {
                return Integer.valueOf(0);
            }

            return "N/A";
        }
        String s = null;

        switch (col) {
        case LIDN:
            return Integer.valueOf(j.mIlid);// j.m_fa.lid;
        case FIDN:
            return Integer.valueOf(j.m_fa.fid);
        case AIDN:
            return Integer.valueOf(j.m_fa.aid);
        case EIDN:
            return Integer.valueOf(j.m_fa.eid);
        case GIDN:
            return Integer.valueOf(j.m_fa.gid);
        case AYEA:
            return Integer.valueOf(j.m_fa.anime.yea);
        case AYEN:
            return Integer.valueOf(j.m_fa.anime.yen);
        case AEPS:
            return Integer.valueOf(j.m_fa.anime.eps);
        case ALEP:
            return Integer.valueOf(j.m_fa.anime.lep);
        case FLEN:
            return Integer.valueOf(j.m_fa.len);
        case AKAN:
            s = j.m_fa.anime.kan;
            break;
        case AROM:
            s = j.m_fa.anime.rom;
            break;
        case AENG:
            s = j.m_fa.anime.eng;
            break;
        case ATYP:
            s = j.m_fa.anime.typ;
            break;
        case EKAN:
            s = j.m_fa.ep.kan;
            break;
        case EROM:
            s = j.m_fa.ep.rom;
            break;
        case EENG:
            s = j.m_fa.ep.eng;
            break;
        case ENUM:
            s = j.m_fa.ep.num;
            break;
        case GNAM:
            s = j.m_fa.group.name;
            break;
        case GSHO:
            s = j.m_fa.group.sname;
            break;
        case FDUB:
            s = j.m_fa.dub;
            break;
        case FSUB:
            s = j.m_fa.sub;
            break;
        case FSRC:
            s = j.m_fa.rip;
            break;
        case FQUA:
            s = j.m_fa.qua;
            break;
        case FRES:
            s = j.m_fa.res;
            break;
        case FVID:
            s = j.m_fa.vid;
            break;
        case FAUD:
            s = j.m_fa.aud;
            break;
        case FMDS:
            s = j.m_fa.mds();
            break;
        case FMDA:
            s = j.m_fa.mda();
            break;
        default:
            break;
        }

        return s == null ? "" : s;
    }

    @Override
    public boolean isCellEditable(int row, int col) {
        return false;
    }

    // public void setValueAt(Object obj, int row, int col){
    // }
    @Override
    public String getColumnName(int columnIndex) {
        return TableModelJobs.STRA[columnIndex];
    }

    public int getColumnIndex(String s) {
        for (int i = 0; i < TableModelJobs.STRA.length; i++) {
            if (TableModelJobs.STRA[i].equals(s)) {
                return i;
            }
        }

        return -1;
    }

    public static void formatTable(JTable table) {
        table.setShowGrid(false);
        TableColumnModel m = table.getColumnModel();
        DefaultTableCellRenderer centerRend = new DefaultTableCellRenderer();
        centerRend.setHorizontalAlignment(SwingConstants.CENTER);

        for (int i = 0; i < TableModelJobs.ccnt; i++) {
            if (i != TableModelJobs.FILE) {
                m.getColumn(i).setCellRenderer(centerRend);
            }
        }
    }

    public void updateRow(int id) {
        this.fireTableRowsUpdated(id, id);
    }

    /*
     * public void updateRow(Job j){ try{ updateRow(m_rev[j.mIid]); }catch(Exception
     * e){ updateRow(j.mIid); } }
     */
    public void insertJob(int x) {
        // fireTableRowsInserted(j.mIid, j.mIid);
        fireTableRowsInserted(x, x);
    }

    public int[] convertRow(int row) {
        return new int[] { getRowIndex(row) };

    }

    @Override
    public Job[] getJobs(int row) {
        return new Job[] { (Job) getValueAt(row, TableModelJobs.JOB) };
    }

    public void convertRows(int rows[]) {
        for (int i = 0; i < rows.length; i++) {
            rows[i] = getRowIndex(rows[i]);
        }
    }
}
