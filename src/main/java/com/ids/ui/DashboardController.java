package com.ids.ui;

import com.ids.services.Connection;
import com.ids.services.ConnectionAnalyzer;
import com.ids.services.PacketCapture;
import com.ids.utils.Alert;

import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.fxml.FXML;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.control.cell.PropertyValueFactory;
import org.pcap4j.core.PcapNetworkInterface;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

public class DashboardController {

  @FXML
  private TableView<Connection> connectionTable;
  @FXML
  private TableColumn<Connection, String> sourceIpCol;
  @FXML
  private TableColumn<Connection, String> destinationIpCol;
  @FXML
  private TableColumn<Connection, Integer> sourcePortCol;
  @FXML
  private TableColumn<Connection, Integer> destinationPortCol;
  @FXML
  private TableColumn<Connection, String> protocolCol;
  @FXML
  private TableColumn<Connection, Long> packetCountCol;
  @FXML
  private TableColumn<Connection, Long> byteCountCol;
  @FXML
  private TableColumn<Connection, Long> durationCol;

  @FXML
  private TableView<Map.Entry<String, Integer>> packetStatisticsTable;
  @FXML
  private TableColumn<Map.Entry<String, Integer>, String> statisticCol;
  @FXML
  private TableColumn<Map.Entry<String, Integer>, Integer> valueCol;

  @FXML
  private TableView<Alert> alertsTable;
  @FXML
  private TableColumn<Alert, String> timeCol;
  @FXML
  private TableColumn<Alert, String> alertCol;

  private ObservableList<Connection> connectionData = FXCollections.observableArrayList();
  private ObservableList<Map.Entry<String, Integer>> packetStatisticsData = FXCollections.observableArrayList();
  private ObservableList<Alert> alertsData = FXCollections.observableArrayList();

  private Map<String, Integer> incomingPacketsCount = new HashMap<>();
  private Map<String, Integer> outgoingPacketsCount = new HashMap<>();
  private ConnectionAnalyzer connectionAnalyzer;

  @FXML
  public void initialize() {
    sourceIpCol.setCellValueFactory(new PropertyValueFactory<>("sourceIp"));
    destinationIpCol.setCellValueFactory(new PropertyValueFactory<>("destinationIp"));
    sourcePortCol.setCellValueFactory(new PropertyValueFactory<>("sourcePort"));
    destinationPortCol.setCellValueFactory(new PropertyValueFactory<>("destinationPort"));
    protocolCol.setCellValueFactory(new PropertyValueFactory<>("protocol"));
    packetCountCol.setCellValueFactory(new PropertyValueFactory<>("packetCount"));
    byteCountCol.setCellValueFactory(new PropertyValueFactory<>("byteCount"));
    durationCol.setCellValueFactory(new PropertyValueFactory<>("duration"));

    connectionTable.setItems(connectionData);

    statisticCol.setCellValueFactory(data -> new javafx.beans.property.SimpleStringProperty(data.getValue().getKey()));
    valueCol.setCellValueFactory(
        data -> new javafx.beans.property.SimpleIntegerProperty(data.getValue().getValue()).asObject());

    packetStatisticsTable.setItems(packetStatisticsData);

    timeCol.setCellValueFactory(new PropertyValueFactory<>("time"));
    alertCol.setCellValueFactory(new PropertyValueFactory<>("message"));

    alertsTable.setItems(alertsData);

    // For testing purposes, add some dummy data
    addDummyData();
  }

  public void initializeDashboard(PcapNetworkInterface selectedInterface) {
    try {
      PacketCapture packetCapture = new PacketCapture(selectedInterface);
      connectionAnalyzer = new ConnectionAnalyzer();

      packetCapture.startCapture("output.pcap");
      connectionAnalyzer.startAnalyzing(packetCapture, 60000, 1000);

      startUpdatingTables();

    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  private void startUpdatingTables() {
    new Thread(() -> {
      while (true) {
        Collection<Connection> activeConnections = connectionAnalyzer.getActiveConnections();
        Platform.runLater(() -> {
          connectionData.setAll(activeConnections);
        });

        Map<String, Integer> packetStatistics = new HashMap<>();
        packetStatistics.put("Incoming Packets",
            incomingPacketsCount.values().stream().mapToInt(Integer::intValue).sum());
        packetStatistics.put("Outgoing Packets",
            outgoingPacketsCount.values().stream().mapToInt(Integer::intValue).sum());

        Platform.runLater(() -> {
          packetStatisticsData.setAll(packetStatistics.entrySet());
        });

        try {
          Thread.sleep(5000); // Update every 5 seconds
        } catch (InterruptedException e) {
          e.printStackTrace();
        }
      }
    }).start();
  }

  private void addDummyData() {
    connectionData.add(new Connection("192.168.1.1", "192.168.1.2", 12345, 80, "TCP"));
    connectionData.add(new Connection("192.168.1.3", "192.168.1.4", 12346, 443, "UDP"));

    incomingPacketsCount.put("192.168.1.2", 10);
    incomingPacketsCount.put("192.168.1.4", 20);

    outgoingPacketsCount.put("192.168.1.1", 15);
    outgoingPacketsCount.put("192.168.1.3", 25);

    alertsData.add(new Alert("12:00", "High traffic detected"));
    alertsData.add(new Alert("12:05", "Potential attack detected"));
  }
}