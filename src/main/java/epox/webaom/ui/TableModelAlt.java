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
 * Created on 25.des.2005 16:29:23
 * Filename: AnimeModel.java
 */
package epox.webaom.ui;

import javax.swing.SwingConstants;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableColumnModel;

import com.sun.swing.AbstractTreeTableModel;
import com.sun.swing.TreeTableModel;

import epox.util.U;
import epox.webaom.A;
import epox.webaom.data.AFile;
import epox.webaom.data.AG;
import epox.webaom.data.Anime;
import epox.webaom.data.Base;
import epox.webaom.data.Ep;
import epox.webaom.data.Path;

public class TableModelAlt extends AbstractTreeTableModel {
    public static final int NAME = 0, PRCT = 1, LAST = 2, TYPE = 3, YEAR = 4, NUMB = 5, SIZE = 6;
    static protected String[] cNames = { "Name", "%", "M", "Type", "Year", "Number", "Size" };
    static protected Class<?>[] cTypes = { TreeTableModel.class, String.class, Character.class, Integer.class,
            Integer.class, Integer.class, String.class };

    public TableModelAlt() {
        super(A.p);
    }

    @Override
    public int getColumnCount() {
        return TableModelAlt.cNames.length;
    }

    @Override
    public String getColumnName(int c) {
        return TableModelAlt.cNames[c];
    }

    @Override
    public Class<?> getColumnClass(int c) {
        return TableModelAlt.cTypes[c];
    }

    @Override
    public Object getValueAt(Object node, int c) {

        if (node instanceof Base g) {

            switch (c) {
            case SIZE:
                return U.sbyte(g.mLs);
            default:
                break;
            }
        }

        if (node instanceof Anime a) {
            return switch (c) {
            case NAME -> a.rom;
            case TYPE -> a.typ;
            case YEAR -> Integer.valueOf(a.yea);
            case NUMB -> Integer.valueOf(a.size());
            case PRCT -> Integer.valueOf(a.getPct()); // return new Integer(a.getPct());
            case LAST -> Character.valueOf(a.miss());
            default -> null;
            };
        }

        if (node instanceof Ep e) {
            return switch (c) {
            case NUMB -> Integer.valueOf(e.size());
            default -> null;
            };
        }

        if (node instanceof AFile f) {
            return switch (c) {
            case TYPE -> f.getJob() == null ? null : f.getJob().getStatusText();
            case YEAR -> f.vid; // new Integer(f.fid);
            case NUMB -> f.aud; // U.sbyte(f.mLs);
            default -> null;
            };
        }

        if (node instanceof AG g) {
            return switch (c) {
            case NUMB -> Integer.valueOf(g.size());
            case PRCT -> Integer.valueOf(g.getPct());
            default -> null;
            };
        }

        if (node instanceof Path p) {
            return switch (c) {
            case NUMB -> Integer.valueOf(p.size());
            default -> null;
            };
        }

        if (node == A.p) {
            return switch (c) {
            case NAME -> A.p.toString();
            case NUMB -> Integer.valueOf(A.p.size());
            default -> null;
            };
        }
        U.err("AnimeModel: Unknown object: " + node);

        return null;
    }

    @Override
    public Object getChild(Object parent, int index) {
        if (parent instanceof Base) {
            return ((Base) parent).get(index);
        }
        U.err(parent);

        return null;
    }

    @Override
    public int getChildCount(Object parent) {
        Base p = (Base) parent;
        p.mkArray();

        return p.size();
    }

    @Override
    public boolean isLeaf(Object node) {
        if (node instanceof AFile) {
            return true;
        }

        return false;
    }

    public void formatTable(TableColumnModel m) {
        m.getColumn(TableModelAlt.NAME).setPreferredWidth(1200);
        m.getColumn(TableModelAlt.TYPE).setPreferredWidth(200);
        m.getColumn(TableModelAlt.YEAR).setPreferredWidth(100);
        m.getColumn(TableModelAlt.NUMB).setPreferredWidth(100);
        m.getColumn(TableModelAlt.SIZE).setPreferredWidth(140);
        m.getColumn(TableModelAlt.PRCT).setPreferredWidth(60);
        m.getColumn(TableModelAlt.LAST).setPreferredWidth(30);
        DefaultTableCellRenderer r0 = new DefaultTableCellRenderer();
        r0.setHorizontalAlignment(SwingConstants.CENTER);
        // m.getColumn(AnimeModel.NAME).setCellRenderer(centerRend);
        m.getColumn(TableModelAlt.TYPE).setCellRenderer(r0);
        m.getColumn(TableModelAlt.YEAR).setCellRenderer(r0);
        m.getColumn(TableModelAlt.NUMB).setCellRenderer(r0);
        m.getColumn(TableModelAlt.PRCT).setCellRenderer(r0);
        m.getColumn(TableModelAlt.LAST).setCellRenderer(r0);
        DefaultTableCellRenderer r1 = new DefaultTableCellRenderer();
        r1.setHorizontalAlignment(SwingConstants.RIGHT);
        m.getColumn(TableModelAlt.SIZE).setCellRenderer(r1);
    }
}
