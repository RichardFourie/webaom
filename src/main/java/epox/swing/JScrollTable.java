/*
 * Created on 28.mai.2006 11:14:54
 * Filename: JScrollTable.java
 */
package epox.swing;

import java.awt.Point;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;

import javax.swing.JScrollPane;
import javax.swing.JTable;

public class JScrollTable extends JScrollPane implements MouseListener {
    private static final long serialVersionUID = -1927104383058088375L;
    private JTable m_jt;

    public JScrollTable(JTable jt) {
        super(jt);
        m_jt = jt;
        getViewport().setBackground(java.awt.Color.white);

        setFocusable(true);
        addMouseListener(this);
    }

    public int getTopVisibleRow() {
        return m_jt.rowAtPoint(getViewport().getViewPosition());
    }

    public int getBottomVisibleRow() {
        int y = getViewport().getViewPosition().y;
        y += getViewport().getExtentSize().getHeight();
        int row = m_jt.rowAtPoint(new Point(0, y));
        return (row > -1) ? row : (m_jt.getRowCount() - 1);
    }

    @Override
    public void mouseClicked(MouseEvent e) {
        requestFocusInWindow();
    }

    @Override
    public void mousePressed(MouseEvent e) {
        //
    }

    @Override
    public void mouseReleased(MouseEvent e) {
        //
    }

    @Override
    public void mouseEntered(MouseEvent e) {
        //
    }

    @Override
    public void mouseExited(MouseEvent e) {
        //
    }
}
