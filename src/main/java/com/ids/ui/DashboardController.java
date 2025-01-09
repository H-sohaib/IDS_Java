package com.ids.ui;

import com.ids.core.Connection;
import com.ids.core.ConnectionAnalyzer;
import com.ids.core.PacketCapture;
import com.ids.core.PacketStatistic;
import com.ids.utils.Alert;

import javafx.application.Platform;
import javafx.beans.property.SimpleStringProperty;
import javafx.beans.property.StringProperty;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.fxml.FXML;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.scene.text.Text;
import javafx.beans.property.SimpleStringProperty;
import javafx.beans.property.StringProperty;

import org.pcap4j.core.PcapNetworkInterface;

import java.time.format.DateTimeFormatter;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

public class DashboardController {
  @FXML
  private Text trafficVolumeText;
  @FXML
  private Text alertCountText;
  // @FXML
  // private Text bandwidthText;

  private StringProperty trafficVolume = new SimpleStringProperty("0 KB");
  private StringProperty alertCount = new SimpleStringProperty("0");
  // private StringProperty bandwidth = new SimpleStringProperty("0 bps");

  private long previousTraffic = 0;
  private long previousTime = System.currentTimeMillis();

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
  private TableColumn<Alert, String> alertCol;
  @FXML
  private TableColumn<Alert, String> timeCol;
  @FXML
  private TableColumn<Alert, String> descriptionCol;

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

    alertCol.setCellValueFactory(new PropertyValueFactory<>("alert"));
    timeCol.setCellValueFactory(cellData -> {
      DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
      return new javafx.beans.property.SimpleStringProperty(cellData.getValue().getDateTime().format(formatter));
    });
    descriptionCol.setCellValueFactory(new PropertyValueFactory<>("description"));

    alertsTable.setItems(alertsData);

    trafficVolumeText.textProperty().bind(trafficVolume);
    alertCountText.textProperty().bind(alertCount);
    // bandwidthText.textProperty().bind(bandwidth);
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

        long currentTraffic = activeConnections.stream()
            .mapToLong(Connection::getByteCount)
            .sum();
        long currentTime = System.currentTimeMillis();
        // Update traffic volume
        Platform.runLater(() -> trafficVolume.set(formatDataSize(currentTraffic)));
        // // Update bandwidth (bits per second)
        // long deltaTime = currentTime - previousTime;
        // if (deltaTime > 0) {
        // long bandwidthBps = (currentTraffic - previousTraffic) * 8 * 1000 /
        // deltaTime;
        // Platform.runLater(() -> bandwidth.set(bandwidthBps + " bps"));
        // }
        previousTraffic = currentTraffic;
        previousTime = currentTime;

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

        // Generate and display alerts
        List<Alert> newAlerts = connectionAnalyzer.generateAlerts();
        Platform.runLater(() -> {
          for (Alert newAlert : newAlerts) {
            Optional<Alert> existingAlert = alertsData.stream()
                .filter(alert -> alert.getAlert().equals(newAlert.getAlert()) &&
                    alert.getDescription().equals(newAlert.getDescription()))
                .findFirst();
            if (existingAlert.isPresent()) {
              existingAlert.get().setDateTime(newAlert.getDateTime());
            } else {
              alertsData.add(newAlert);
            }
          }
          alertCount.set(String.valueOf(alertsData.size()));
        });

        try {
          Thread.sleep(5000); // Update every 5 seconds
        } catch (InterruptedException e) {
          e.printStackTrace();
        }
      }
    }).start();
  }

  private String formatDataSize(long bytes) {
    if (bytes < 1024)
      return bytes + " B";
    int exp = (int) (Math.log(bytes) / Math.log(1024));
    char prefix = "KMGTPE".charAt(exp - 1);
    return String.format("%.1f %sB", bytes / Math.pow(1024, exp), prefix);
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