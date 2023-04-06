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
 * @version 	1.07
 * @author 		epoximator
 */

package epox.swing;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.PrintStream;
import java.text.DecimalFormat;

import javax.swing.JPanel;
import javax.swing.JScrollBar;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;

import epox.util.U;
import epox.webaom.A;

public class JPanelDebug extends JPanel {
    /**
     *
     */
    private static final long serialVersionUID = -2058550654886526702L;
    public static DecimalFormat nf = new DecimalFormat("000.00");
    private PrintStream perr;
    private PrintStream pout;
    private File log;
    protected JTextArea jta;
    protected JScrollBar jsb;
    protected boolean log_file = false;
    protected Updater updater;

    public JPanelDebug(String file, boolean out, boolean err, boolean echo_out, boolean echo_err) {
        super(new java.awt.BorderLayout());
        jta = new JTextArea();
        jta.setMargin(new java.awt.Insets(2, 2, 2, 2));
        jta.append("Please report bugs! (http://wiki.anidb.net/w/User:Epoximator) Version:" + A.S_VER + "\r\n");
        JScrollPane scroll = new JScrollPane(jta);
        jsb = scroll.getVerticalScrollBar();
        add(scroll);

        try {
            FileOutputStream os = null;

            if (file != null) {
                log_file = true;
                log = new File(file);
                os = new FileOutputStream(log);
            }

            perr = System.err;
            pout = System.out;

            WinStream errstream = new WinStream(os, echo_err, perr);
            WinStream outstream = new WinStream(os, echo_out, pout);

            if (err) {
                System.setErr(errstream);
            }

            if (out) {
                System.setOut(outstream);
            }
        } catch (FileNotFoundException e) {
            jta.append("Could not openfile" + file);
        }
        updater = new Updater();
    }

    public JPanelDebug(String file) {
        this(file, true, true, false, true);
    }

    protected class Updater implements Runnable {
        @Override
        public void run() {

            if (!jsb.getValueIsAdjusting()) {
                jsb.setValue(jsb.getMaximum());
            }
        }
    }

    private class WinStream extends PrintStream {
        PrintStream pecho;
        boolean echo, newl = true;
        long t0, t1;

        public WinStream(FileOutputStream stream, boolean echo, PrintStream pecho) {
            super(stream != null ? stream : pecho);
            this.pecho = pecho;
            this.echo = echo;
            this.t0 = System.currentTimeMillis();
        }

        private synchronized void append(String str) {
            t1 = System.currentTimeMillis();

            if (str == "\n") {

                if (!newl) {
                    jta.append("\n");
                }
                newl = true;
                t0 = t1;

            } else {
                String pre = "[" + U.time() + "|" + JPanelDebug.nf.format((float) (t1 - t0) / 1000) + "] "
                        + Thread.currentThread().getName() + ": ";

                if (str.indexOf('\n') < 0) {

                    if (newl) {
                        jta.append(pre);
                    }
                    jta.append(str);
                    newl = false;
                } else {
                    String arg[] = U.split(str, '\n');

                    for (String element : arg) {

                        if (newl) {
                            jta.append(pre);
                        }
                        jta.append(element + "\n");
                        newl = true;
                    }
                    t0 = t1;
                }
            }

            if (jta.isVisible()) {
                javax.swing.SwingUtilities.invokeLater(updater);
            }
        }

        @Override
        public void print(boolean x) {

            if (echo) {
                pecho.print(x);
            }

            if (log_file) {
                super.print(x);
            }
            append(x + "");
        }

        @Override
        public void print(char x) {

            if (echo) {
                pecho.print(x);
            }

            if (log_file) {
                super.print(x);
            }
            append(x + "");
        }

        @Override
        public void print(int x) {

            if (echo) {
                pecho.print(x);
            }

            if (log_file) {
                super.print(x);
            }
            append(x + "");
        }

        @Override
        public void print(long x) {

            if (echo) {
                pecho.print(x);
            }

            if (log_file) {
                super.print(x);
            }
            append(x + "");
        }

        @Override
        public void print(float x) {

            if (echo) {
                pecho.print(x);
            }

            if (log_file) {
                super.print(x);
            }
            append(x + "");
        }

        @Override
        public void print(double x) {

            if (echo) {
                pecho.print(x);
            }

            if (log_file) {
                super.print(x);
            }
            append(x + "");
        }

        @Override
        public void print(char x[]) {

            if (echo) {
                pecho.print(x);
            }

            if (log_file) {
                super.print(new String(x));
            }
            append(new String(x));
        }

        @Override
        public void print(String x) {

            if (x == null) {
                x = "null";
            }

            if (echo) {
                pecho.print(/* Thread.currentThread().getName()+": "+ */x);
            }

            if (log_file) {
                super.print(x);
            }

            if (x.endsWith("\n")) {
                newl = true;
            }
            append(x);
        }

        @Override
        public void print(Object x) {

            if (echo) {
                pecho.print(x);
            }

            if (log_file) {
                super.print(x.toString());
            }
            append("" + x);
        }

        @Override
        public void println() {

            if (echo) {
                pecho.println();
            }

            if (log_file) {
                super.println();
            }
            // newl = true;
            append("\n");
            // jta.append("\n");
        }

        @Override
        public void println(boolean x) {
            print(x);
            println();
        }

        @Override
        public void println(char x) {
            print(x);
            println();
        }

        @Override
        public void println(int x) {
            print(x);
            println();
        }

        @Override
        public void println(long x) {
            print(x);
            println();
        }

        @Override
        public void println(float x) {
            print(x);
            println();
        }

        @Override
        public void println(double x) {
            print(x);
            println();
        }

        @Override
        public void println(char x[]) {
            print(x);
            println();
        }

        @Override
        public void println(String x) {
            print(x);
            println();
        }

        @Override
        public void println(Object x) {
            print(x);
            println();
        }
    }
}
