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
 * @version 	1.09, 1.05
 * @author 		epoximator
 */
package epox.webaom.ui;

import java.util.ArrayList;

import javax.swing.JTable;
import javax.swing.SwingConstants;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableColumnModel;

import epox.util.DSData;

public class TableModelDS extends AbstractTableModel {
    /**
     *
     */
    private static final long serialVersionUID = -2394223733131528820L;

    public static final int SEL = 0, SRC = 1, DST = 2;

    private ArrayList<DSData> data;
    private String stitle0, stitle1;
    private DSData dummy;

    public TableModelDS(ArrayList<DSData> d, String s0, String s1) {
        setData(d);
        stitle0 = s0;
        stitle1 = s1;
        dummy = new DSData("", "", false);
    }

    public ArrayList<DSData> getData() {
        return data;
    }

    public void setData(ArrayList<DSData> d) {
        data = d;
    }

    @Override
    public int getColumnCount() {
        return 3;
    }

    @Override
    public Class<?> getColumnClass(int col) {
        return switch (col) {
        case SEL -> Boolean.class;
        default -> String.class;
        };
    }

    @Override
    public int getRowCount() {
        return data.size() + 1;
    }

    @Override
    public Object getValueAt(int row, int col) {
        DSData rd;

        if (row == data.size()) {
            rd = dummy;
        } else {
            rd = data.get(row);// !
        }

        switch (col) {
        case SEL:
            return rd.sel;
        case SRC:
            return rd.src;
        case DST:
            return rd.dst;
        }
        return null;
    }

    @Override
    public boolean isCellEditable(int row, int col) {
        return true;
    }

    @Override
    public void setValueAt(Object obj, int row, int col) {
        DSData rd;

        if (row == data.size()) {
            rd = new DSData("", "", false);
            data.add(rd);
            fireTableRowsInserted(row, row);
        } else {
            rd = data.get(row);// !
        }

        if (rd != null) {

            switch (col) {
            case SEL:
                if (rd.src.length() > 0) {
                    rd.sel = (Boolean) obj;
                }
                break;
            case SRC:
                rd.src = (String) obj;
                if (rd.src.length() == 0) {
                    data.remove(rd);
                }
                break;
            case DST:
                rd.dst = getString(obj);
                break;
            }
        }
    }

    private String getString(Object o) {
        String str = (String) o;

        for (DSData rd : data) {

            if (rd.src.equals(str)) {
                return "";
            }
        }
        return str;
    }

    @Override
    public String getColumnName(int columnIndex) {

        switch (columnIndex) {
        case SEL:
            return "Enabled";
        case SRC:
            return stitle0;
        case DST:
            return stitle1;
        }
        return "No such column!";
    }

    public static void formatTable(JTable table) {
        TableColumnModel m = table.getColumnModel();
        m.getColumn(0).setMaxWidth(50);
        m.getColumn(1).setPreferredWidth(100);
        m.getColumn(2).setPreferredWidth(100);
        DefaultTableCellRenderer centerRend = new DefaultTableCellRenderer();
        centerRend.setHorizontalAlignment(SwingConstants.CENTER);
        m.getColumn(1).setCellRenderer(centerRend);
        m.getColumn(2).setCellRenderer(centerRend);
    }
}
