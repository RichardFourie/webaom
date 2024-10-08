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
 * Created on 29.01.05
 *
 * @version 	04 (1.09,1.07,1.06,1.01)
 * @author 		epoximator
 */
package epox.webaom;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.StringTokenizer;

import epox.swing.UniqueStringList;

public class FileHandler {
    public UniqueStringList m_ext;
    public FileFilter1 m_ff;

    public FileHandler() {
        m_ext = new UniqueStringList(Options.S_SEP);
        m_ff = new FileFilter1();
    }

    public synchronized void addExt(String str) {
        m_ext.add(str);
    }

    public synchronized void removeExt(int i) {
        m_ext.removeElementAt(i);
    }

    public synchronized boolean addFile(File file) {
        if ((m_ext.includes(FileHandler.getExtension(file)) || m_ext.getSize() == 0) && !A.jobs.has(file)
                && !FileHandler.locked(file)) {
            Job j = A.jobs.add(file);

            if (j != null) {
                j.updateHealth(Job.H_PAUSED);
                return true;
            }
        }

        return false;
    }

    protected static String getExtension(File file) {
        int i = file.getName().lastIndexOf(".");

        if (i < 0) {
            return null;
        }

        return file.getName().substring(i + 1).toLowerCase();
    }

    private static boolean locked(File f) {
        try (InputStream fis = new FileInputStream(f)) {
            return false;
        } catch (IOException e) {
            e.printStackTrace();
        }

        return true;
    }

    public synchronized void opts(Options o) {
        o.setS(Options.S_EXTENSN, m_ext.toString());
    }

    public synchronized void optl(Options o) {
        StringTokenizer st = new StringTokenizer(o.getS(Options.S_EXTENSN), Options.S_SEP);

        while (st.hasMoreTokens()) {
            m_ext.add(st.nextToken());
        }
    }

    protected class FileFilter1 extends javax.swing.filechooser.FileFilter implements java.io.FileFilter {
        @Override
        public boolean accept(File file) {
            if (file.isDirectory() || m_ext.includes(FileHandler.getExtension(file)) || m_ext.getSize() == 0) {
                return true;
            }

            return false;
        }

        @Override
        public String getDescription() {
            return "Me WANTS!";
        }
    }
}
