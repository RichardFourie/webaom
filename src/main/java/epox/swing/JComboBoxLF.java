/*
 * Created on 30. juni. 2007 00.05.11
 * Filename: JComboBoxLF.java
 */
package epox.swing;

import java.awt.Component;

import javax.swing.DefaultComboBoxModel;
import javax.swing.JComboBox;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;
import javax.swing.UIManager.LookAndFeelInfo;

public class JComboBoxLF extends JComboBox<String> {

    private static final long serialVersionUID = -5972227662435340198L;

    private static final String DEFAULT_LOOK_AND_FEEL = UIManager.getSystemLookAndFeelClassName();

    protected static final LookAndFeelInfo lf[] = UIManager.getInstalledLookAndFeels();

    public JComboBoxLF(final Component c) {
        super(new DefaultComboBoxModel<String>() {
            private static final long serialVersionUID = 4847538324426109833L;

            @Override
            public String getElementAt(final int index) {
                return JComboBoxLF.lf[index].getName();
            }

            @Override
            public int getSize() {
                return JComboBoxLF.lf.length;
            }
        });
        addActionListener(e -> {
            try {
                UIManager.setLookAndFeel(JComboBoxLF.lf[getSelectedIndex()].getClassName());
            } catch (Exception x) {
                x.printStackTrace();
            }

            SwingUtilities.updateComponentTreeUI(c);
        });

        int i;
        for (i = 0; i < JComboBoxLF.lf.length; i++) {
            if (DEFAULT_LOOK_AND_FEEL.equals(JComboBoxLF.lf[i].getClassName())) {
                break;
            }
        }

        setSelectedIndex(i);
        setToolTipText("Select wanted look and feel here.");
    }
}
