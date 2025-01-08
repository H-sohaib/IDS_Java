package com.ids.ui;

import com.ids.services.Connection;
import com.ids.services.ConnectionAnalyzer;
import com.ids.services.PacketCapture;
import com.ids.services.PacketStatistic;
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
  private TableView<PacketStatistic> packetStatisticsTable;
  @FXML
  private TableColumn<PacketStatistic, String> ipCol;
  @FXML
  private TableColumn<PacketStatistic, Integer> incomingPacketsCol;
  @FXML
  private TableColumn<PacketStatistic, Integer> outgoingPacketsCol;

  @FXML
  private TableView<Alert> alertsTable;
  @FXML
  private TableColumn<Alert, String> descriptionCol;
  @FXML
  private TableColumn<Alert, String> alertCol;

  private ObservableList<Connection> connectionData = FXCollections.observableArrayList();
  private ObservableList<PacketStatistic> packetStatisticsData = FXCollections.observableArrayList();
  private ObservableList<Alert> alertsData = FXCollections.observableArrayList();

  // private Map<String, Integer> incomingPacketsCount = new HashMap<>();
  // private Map<String, Integer> outgoingPacketsCount = new HashMap<>();
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

    ipCol.setCellValueFactory(new PropertyValueFactory<>("ip"));
    incomingPacketsCol.setCellValueFactory(new PropertyValueFactory<>("incomingPackets"));
    outgoingPacketsCol.setCellValueFactory(new PropertyValueFactory<>("outgoingPackets"));

    packetStatisticsTable.setItems(packetStatisticsData);

    descriptionCol.setCellValueFactory(new PropertyValueFactory<>("time"));
    alertCol.setCellValueFactory(new PropertyValueFactory<>("message"));

    alertsTable.setItems(alertsData);

    // For testing purposes, add some dummy data
    // addDummyData();
  }

  public void initializeDashboard(PcapNetworkInterface selectedInterface, String captureFilter) {
    try {
      PacketCapture packetCapture = new PacketCapture(selectedInterface, captureFilter);
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

        Map<String, PacketStatistic> packetStatistics = new HashMap<>();
        connectionAnalyzer.getIncomingPacketsCount().forEach((ip, count) -> {
          packetStatistics.putIfAbsent(ip, new PacketStatistic(ip, 0, 0));
          packetStatistics.get(ip).setIncomingPackets(count);
        });

        connectionAnalyzer.getOutgoingPacketsCount().forEach((ip, count) -> {
          packetStatistics.putIfAbsent(ip, new PacketStatistic(ip, 0, 0));
          packetStatistics.get(ip).setOutgoingPackets(count);
        });

        Platform.runLater(() -> {
          packetStatisticsData.setAll(packetStatistics.values());
        });

        try {
          Thread.sleep(5000); // Update every 5 seconds
        } catch (InterruptedException e) {
          e.printStackTrace();
        }
      }
    }).start();
  }

  // private void addDummyData() {
  // connectionData.add(new Connection("192.168.1.1", "192.168.1.2", 12345, 80,
  // "TCP"));
  // connectionData.add(new Connection("192.168.1.3", "192.168.1.4", 12346, 443,
  // "UDP"));

  // incomingPacketsCount.put("192.168.1.2", 10);
  // incomingPacketsCount.put("192.168.1.4", 20);

  // outgoingPacketsCount.put("192.168.1.1", 15);
  // outgoingPacketsCount.put("192.168.1.3", 25);

  // alertsData.add(new Alert("12:00", "High traffic detected"));
  // alertsData.add(new Alert("12:05", "Potential attack detected"));
  // }

}