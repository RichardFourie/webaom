/*
 * Created on 09.mar.2006 20:51:26
 * Filename: JTableJobs.java
 */
package epox.webaom.ui;

import java.awt.Color;
import java.awt.Component;
import java.awt.Toolkit;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.Transferable;
import java.awt.dnd.DnDConstants;
import java.awt.dnd.DropTarget;
import java.awt.dnd.DropTargetDragEvent;
import java.awt.dnd.DropTargetDropEvent;
import java.awt.dnd.DropTargetEvent;
import java.awt.dnd.DropTargetListener;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.awt.event.KeyListener;
import java.io.File;
import java.util.Arrays;
import java.util.List;

import javax.swing.AbstractAction;
import javax.swing.KeyStroke;
import javax.swing.table.TableCellRenderer;

import epox.swing.JTableSortable;
import epox.webaom.A;
import epox.webaom.Job;

public class JTableJobs extends JTableSortable implements DropTargetListener, KeyListener {
    private static final long serialVersionUID = 8151757579007898894L;
    private TableModelJobs m_jlm;

    @SuppressWarnings("unused")
    public JTableJobs(TableModelJobs jlm) {
        super(jlm);
        m_jlm = jlm;
        final JPopupMenuM pop = new JPopupMenuM(this, jlm);
        A.com0 = pop;
        addMouseListener(pop);

        addMouseListener(new MouseAdapterJob(this, jlm, A.jobs));
        getInputMap().put(KeyStroke.getKeyStroke("ESCAPE"), "stop");
        getActionMap().put("stop", new AbstractAction() {
            private static final long serialVersionUID = -4207187219784505189L;

            @Override
            public void actionPerformed(ActionEvent e) {
                pop.stop();
            }
        });
        addKeyListener(new KeyAdapterJob(this, jlm));

        new DropTarget(this, this);
        addKeyListener(this);
    }

    private final Color c_dio = new Color(0, 102, 153);
    private final Color c_nio = new Color(182, 0, 20);
    private final Color c_mis = new Color(100, 100, 100);
    private final Color c_inv = new Color(255, 180, 180);

    @Override
    public Component prepareRenderer(TableCellRenderer renderer, int row, int col) {
        Component c = super.prepareRenderer(renderer, row, col);

        if (isSelected(row)) {
            return c;
        }

        Job j = (Job) m_jlm.getValueAt(row, TableModelJobs.JOB);

        if (j.isCorrupt()) {
            c.setBackground(c_inv);
            c.setForeground(Color.black);
        } else {
            c.setBackground(this.getBackground());

            if (j.check(Job.D_DIO | Job.S_DOING)) {
                c.setForeground(c_dio);
            } else if (j.check(Job.D_NIO | Job.S_DOING)) {
                c.setForeground(c_nio);
            } else if (j.check(Job.H_MISSING)) {
                c.setForeground(c_mis);
            } else {
                c.setForeground(Color.black);
            }
        }

        return c;
    }

    private boolean isSelected(int row) {
        int[] a = getSelectedRows();
        Arrays.sort(a);

        return Arrays.binarySearch(a, row) >= 0;
    }

    public boolean upd = true;

    /*
     * public void updateUI(){ if(!isEditing()&&upd) SwingUtilities.invokeLater(new
     * Runnable(){
     *
     * @SuppressWarnings("synthetic-access") public void run(){
     * JTableJobs.super.updateUI(); } }); }
     */
    /*
     * protected boolean processKeyBinding(KeyStroke ks, KeyEvent e, int condition,
     * boolean pressed) { boolean retValue = super.processKeyBinding(ks, e,
     * condition, pressed); A.dialog("HI","HO"); return retValue; }
     */
    @Override
    public void dragEnter(DropTargetDragEvent dtde) {
        // dtde.acceptDrag(DnDConstants.ACTION_COPY_OR_MOVE);
    }

    @Override
    public void dragOver(DropTargetDragEvent dtde) {
        //
    }

    @Override
    public void dropActionChanged(DropTargetDragEvent dtde) {
        //
    }

    @Override
    public void dragExit(DropTargetEvent dte) {
        //
    }

    @Override
    public void drop(DropTargetDropEvent dtde) {
        try {
            Transferable t = dtde.getTransferable();

            if (t.isDataFlavorSupported(DataFlavor.javaFileListFlavor)) {
                dtde.acceptDrop(DnDConstants.ACTION_COPY);

                if (JTableJobs.paste(t)) {
                    dtde.getDropTargetContext().dropComplete(true);
                }
            } else {
                dtde.rejectDrop();
            }
        } catch (Exception e) {
            e.printStackTrace();
            dtde.rejectDrop();
        }
    }

    @Override
    public void keyTyped(KeyEvent e) {
        // System.err.println(e);
    }

    @Override
    public void keyPressed(KeyEvent e) {
        // System.err.println(e.getKeyCode()+" "+e.isControlDown());
        if (e.getKeyCode() == 86 && e.isControlDown()) {
            JTableJobs.paste(Toolkit.getDefaultToolkit().getSystemClipboard().getContents(null));
            e.consume();
        }
    }

    @Override
    public void keyReleased(KeyEvent e) {
        //
    }

    @SuppressWarnings("unchecked")
    private static boolean paste(Transferable t) {
        if (t.isDataFlavorSupported(DataFlavor.javaFileListFlavor)) {
            try {
                List<File> l = (List<File>) t.getTransferData(DataFlavor.javaFileListFlavor);
                File f[] = (File[]) l.toArray();
                Arrays.sort(f);
                A.gui.select(f);

                return true;
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        return false;
    }
}
