package com.ids.ui;

// import com.ids.services.ConnectionAnalyzer;
// import com.ids.services.PacketCapture;

import javafx.collections.FXCollections;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.control.ComboBox;
import javafx.scene.control.ListCell;
import javafx.scene.control.ListView;
import javafx.stage.Stage;
import javafx.util.Callback;

import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;

import java.io.IOException;
import java.util.List;

public class InterfaceSelectionController {

  @FXML
  private ComboBox<PcapNetworkInterface> interfaceComboBox;

  @FXML
  public void initialize() throws PcapNativeException, IOException {
    List<PcapNetworkInterface> allDevs = Pcaps.findAllDevs();
    interfaceComboBox.setItems(FXCollections.observableArrayList(allDevs));

    // Set a custom cell factory to display only the description
    interfaceComboBox.setCellFactory(
        (Callback<ListView<PcapNetworkInterface>, ListCell<PcapNetworkInterface>>) new Callback<ListView<PcapNetworkInterface>, ListCell<PcapNetworkInterface>>() {
          @Override
          public ListCell<PcapNetworkInterface> call(ListView<PcapNetworkInterface> param) {
            return new ListCell<PcapNetworkInterface>() {
              @Override
              protected void updateItem(PcapNetworkInterface item, boolean empty) {
                super.updateItem(item, empty);
                if (item == null || empty) {
                  setText(null);
                } else {
                  setText(item.getDescription());
                }
              }
            };
          }
        });

    // Set a custom display for the selected item
    interfaceComboBox.setButtonCell(new ListCell<PcapNetworkInterface>() {
      @Override
      protected void updateItem(PcapNetworkInterface item, boolean empty) {
        super.updateItem(item, empty);
        if (item == null || empty) {
          setText(null);
        } else {
          setText(item.getDescription());
        }
      }
    });
  }

  @FXML
  public void launchDashboard() {
    PcapNetworkInterface selectedInterface = interfaceComboBox.getSelectionModel().getSelectedItem();

    if (selectedInterface != null) {
      try {
        FXMLLoader loader = new FXMLLoader(getClass().getResource("/dashboard.fxml"));
        Parent root = loader.load();
        DashboardController controller = loader.getController();
        controller.initializeDashboard(selectedInterface, "tcp");

        Stage stage = (Stage) interfaceComboBox.getScene().getWindow();
        stage.getScene().setRoot(root);
        stage.setMaximized(true);

      } catch (Exception e) {
        e.printStackTrace();
      }
    }
  }
}