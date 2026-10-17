package br.gov.dere;

import com.formdev.flatlaf.FlatLightLaf;
import javax.swing.*;
import java.awt.*;

public class Main {
  public static void main(String[] args) {
    FlatLightLaf.setup();
    UIManager.put("Component.arc", 12); UIManager.put("Button.arc", 12);
    UIManager.put("TextComponent.arc", 10); UIManager.put("TabbedPane.showTabSeparators", true);
    SwingUtilities.invokeLater(() -> new DereWindow().setVisible(true));
  }
}
