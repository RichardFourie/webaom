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

public class Group extends Base {
    public String name = "none", sname = "";

    public Group(int id) {
        this.id = id;
    }

    @Override
    public String serialize() {
        return name + Base.S + sname;
    }

    @Override
    public String toString() {
        return name + "|" + sname;
    }

    public static final Group none = new Group(0);
}
