package com.ids.core;

import org.pcap4j.packet.Packet;

import com.ids.detector.AttackDetectionContext;
import com.ids.detector.BruteForceDetectionStrategy;
import com.ids.detector.DosDetectionStrategy;
import com.ids.detector.NetworkScanningDetectionStrategy;
import com.ids.utils.Alert;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class ConnectionAnalyzer {

  private Map<String, Integer> incomingPacketsCount = new ConcurrentHashMap<>();
  private Map<String, Integer> outgoingPacketsCount = new ConcurrentHashMap<>();
  private final Map<String, Connection> activeConnections = new ConcurrentHashMap<>();
  private AttackDetectionContext attackDetectionContext = new AttackDetectionContext();

  public ConnectionAnalyzer() {
    attackDetectionContext.addStrategy(new NetworkScanningDetectionStrategy());
    attackDetectionContext.addStrategy(new DosDetectionStrategy());
    // attackDetectionContext.addStrategy(new BruteForceDetectionStrategy());
    // Add multiple detection strategies
  }

  // Analyze a captured packet
  public void analyzePacket(Packet packet) {

    // Extract packet information
    PacketInfo packetInfo = new PacketInfo(packet);

    // Create a unique key for the connection
    String connectionKey = String.format("%s:%d-%s:%d", packetInfo.sourceIp, packetInfo.sourcePort,
        packetInfo.destinationIp, packetInfo.destinationPort);

    // Update or create a new connection entry
    Connection connection = activeConnections.computeIfAbsent(
        connectionKey,
        key -> new Connection(packetInfo.sourceIp, packetInfo.destinationIp, packetInfo.sourcePort,
            packetInfo.destinationPort, packetInfo.protocol));
    connection.update(packetInfo.packetSize);

    // Update incoming and outgoing packet counts
    incomingPacketsCount.merge(packetInfo.destinationIp, 1, Integer::sum);
    outgoingPacketsCount.merge(packetInfo.sourceIp, 1, Integer::sum);

    // Analyze the packet for attack detection
    attackDetectionContext.analyzePacket(packetInfo);
  }

  // Get all active connections
  public Collection<Connection> getActiveConnections() {
    return activeConnections.values();
  }

  // Get incoming packet count per IP address
  public Map<String, Integer> getIncomingPacketsCount() {
    return incomingPacketsCount;
  }

  // Get outgoing packet count per IP address
  public Map<String, Integer> getOutgoingPacketsCount() {
    return outgoingPacketsCount;
  }

  // Clean up inactive connections (optional, based on timeout or inactivity)
  public void cleanupInactiveConnections(long timeout) {
    long currentTime = System.currentTimeMillis();
    activeConnections.entrySet().removeIf(entry -> (currentTime - entry.getValue().endTime) > timeout);
  }

  // Start analyzing captured packets
  public void startAnalyzing(PacketCapture packetCapture, long cleanupTimeout, long analysisInterval) {
    new Thread(() -> {
      while (true) {
        for (Packet packet : packetCapture.getCapturedPackets()) {
          analyzePacket(packet);
        }

        // Optionally, clean up inactive connections
        cleanupInactiveConnections(cleanupTimeout);

        // Sleep for a while before the next analysis
        try {
          Thread.sleep(analysisInterval);
        } catch (InterruptedException e) {
          e.printStackTrace();
        }
      }
    }).start();
  }

  // Print active connections periodically
  public void printActiveConnections(long printInterval) {
    new Thread(() -> {
      while (true) {
        Collection<Connection> activeConnections = getActiveConnections();
        for (Connection connection : activeConnections) {
          System.out.println(connection);
        }

        // Sleep for a while before the next retrieval
        try {
          Thread.sleep(printInterval);
        } catch (InterruptedException e) {
          e.printStackTrace();
        }
      }
    }).start();
  }

  // Print packet statistics periodically
  public void printPacketStatistics(long printInterval) {
    new Thread(() -> {
      while (true) {
        System.out.println("Incoming Packets Count:");
        incomingPacketsCount.forEach((ip, count) -> System.out.println(ip + ": " + count));

        System.out.println("Outgoing Packets Count:");
        outgoingPacketsCount.forEach((ip, count) -> System.out.println(ip + ": " + count));

        // Sleep for a while before the next retrieval
        try {
          Thread.sleep(printInterval);
        } catch (InterruptedException e) {
          e.printStackTrace();
        }
      }
    }).start();
  }

  // Generate alerts based on the detection strategies
  public List<Alert> generateAlerts() {
    return attackDetectionContext.generateAlerts();
  }

}