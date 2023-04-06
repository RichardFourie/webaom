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
 * @version 	1.01
 * @author 		epoximator
 */
package epox.swing;

import java.util.ArrayList;

import javax.swing.ListModel;
import javax.swing.event.ListDataEvent;
import javax.swing.event.ListDataListener;

public class UniqueStringList implements ListModel<String> {
    private ListDataListener ldl;
    private ArrayList<String> table;
    private String sep;

    public UniqueStringList(String s) {
        sep = s;
        table = new ArrayList<>();
    }

    public void add(String ext) {

        if (!table.contains(ext)) {
            int size = getSize();
            table.add(ext);
            ldl.intervalAdded(new ListDataEvent(this, ListDataEvent.INTERVAL_ADDED, size, size));
        }
    }

    /*
     * public void addSilent(String ext){ if(!table.contains(ext)) { table.add(ext);
     * } }
     */
    public String removeElementAt(int i) {
        String str = table.remove(i);// !
        ldl.intervalRemoved(new ListDataEvent(this, ListDataEvent.INTERVAL_REMOVED, i, i));
        return str;
    }

    public void reset() {
        int i = getSize();
        table.clear();
        ldl.intervalRemoved(new ListDataEvent(this, ListDataEvent.INTERVAL_REMOVED, 0, i - 1));
    }

    public boolean includes(String ext) {
        return table.contains(ext);
    }

    @Override
    public String toString() {
        StringBuilder tmp = new StringBuilder();

        for (String element : table) {
            tmp.append(element).append(sep);
        }
        return tmp.toString().trim();
    }

    @Override
    public int getSize() {
        return table.size();
    }

    @Override
    public String getElementAt(int row) {
        return table.get(row);
    }

    public String getStringAt(int row) {
        return table.get(row);
    }

    @Override
    public void addListDataListener(ListDataListener l) {
        ldl = l;
    }

    @Override
    public void removeListDataListener(ListDataListener l) {
        ldl = null;
    }
}
