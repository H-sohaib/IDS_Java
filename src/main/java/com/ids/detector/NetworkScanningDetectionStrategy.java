package com.ids.detector;

import com.ids.core.PacketInfo;
import com.ids.utils.Alert;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;

public class NetworkScanningDetectionStrategy implements AttackDetectionStrategy {
  private static final Logger logger = Logger.getLogger(NetworkScanningDetectionStrategy.class.getName());

  private static final int TIME_WINDOW = 60; // Time window in seconds
  private static final double SYN_ACK_RATIO_THRESHOLD = 3.0;

  private static final Map<String, Threshold> THRESHOLDS = Map.of(
      "PACKET_COUNT", new Threshold(200),
      "PORT_COUNT", new Threshold(50),
      "HOST_COUNT", new Threshold(20),
      "SYN_COUNT", new Threshold(100));

  private final Map<String, TrafficStats> trafficStatsMap = new ConcurrentHashMap<>();

  @Override
  public void analyzePacket(PacketInfo packetInfo) {
    String sourceIp = packetInfo.getSourceIp();
    String destinationIp = packetInfo.getDestinationIp();
    int destinationPort = packetInfo.getDestinationPort();
    String protocol = packetInfo.getProtocol();
    long currentTime = System.currentTimeMillis();

    // Get or initialize traffic stats for the source IP
    TrafficStats stats = trafficStatsMap.computeIfAbsent(sourceIp, ip -> new TrafficStats(currentTime));

    stats.updatePacketCount();
    stats.updateLastSeen(currentTime);

    if (protocol.equals("TCP") || protocol.equals("UDP")) {
      stats.updatePortSet(destinationPort);
    }

    if (protocol.equals("ICMP")) {
      stats.updateHostSet(destinationIp);
    }

    if (protocol.equals("TCP")) {
      if (packetInfo.isSyn() && !packetInfo.isAck()) {
        stats.incrementSynCount();
      } else if (packetInfo.isAck()) {
        stats.incrementAckCount();
      }

      if (stats.getSynCount() > THRESHOLDS.get("SYN_COUNT").getValue() &&
          stats.getSynCount() > stats.getAckCount() * SYN_ACK_RATIO_THRESHOLD) {
        stats.setSynFloodDetected(true);
        logger.info("SYN flood detected from IP: " + sourceIp);
      }
    }

    // Check for port scanning or host discovery
    if ((currentTime - stats.getFirstSeen()) / 1000 <= TIME_WINDOW) {
      if (stats.getPacketCount() > THRESHOLDS.get("PACKET_COUNT").getValue()) {
        if (stats.getPortCount() > THRESHOLDS.get("PORT_COUNT").getValue()) {
          stats.setPortScanDetected(true);
          logger.info("Port scanning detected from IP: " + sourceIp);
        }
        if (stats.getHostCount() > THRESHOLDS.get("HOST_COUNT").getValue()) {
          stats.setHostDiscoveryDetected(true);
          logger.info("Host discovery detected from IP: " + sourceIp);
        }
      }
    } else {
      stats.reset(currentTime);
    }
  }

  @Override
  public boolean isAttackDetected() {
    return trafficStatsMap.values().stream().anyMatch(TrafficStats::isAttackDetected);
  }

  @Override
  public String getAttackDescription() {
    return trafficStatsMap.entrySet().stream()
        .filter(entry -> entry.getValue().isAttackDetected())
        .map(entry -> entry.getKey() + ": " + entry.getValue().getAttackDescription())
        .findFirst()
        .orElse("No attack detected");
  }

  @Override
  public Alert generateAlert() {
    if (isAttackDetected()) {
      String attackDescription = getAttackDescription();
      return new Alert("Network Scanning Attack", attackDescription);
    }
    return null;
  }

  private static class TrafficStats {
    private int packetCount;
    private int synCount;
    private int ackCount;
    private final Set<Integer> portSet = new HashSet<>();
    private final Set<String> hostSet = new HashSet<>();
    private long firstSeen;
    private long lastSeen;
    private boolean portScanDetected;
    private boolean hostDiscoveryDetected;
    private boolean synFloodDetected;

    public TrafficStats(long firstSeen) {
      this.firstSeen = firstSeen;
    }

    public void updatePacketCount() {
      packetCount++;
    }

    public void updateLastSeen(long currentTime) {
      lastSeen = currentTime;
    }

    public void updatePortSet(int port) {
      portSet.add(port);
    }

    public void updateHostSet(String host) {
      hostSet.add(host);
    }

    public void incrementSynCount() {
      synCount++;
    }

    public void incrementAckCount() {
      ackCount++;
    }

    public void reset(long currentTime) {
      packetCount = 0;
      synCount = 0;
      ackCount = 0;
      portSet.clear();
      hostSet.clear();
      firstSeen = currentTime;
    }

    public int getPacketCount() {
      return packetCount;
    }

    public int getPortCount() {
      return portSet.size();
    }

    public int getHostCount() {
      return hostSet.size();
    }

    public int getSynCount() {
      return synCount;
    }

    public int getAckCount() {
      return ackCount;
    }

    public long getFirstSeen() {
      return firstSeen;
    }

    public boolean isAttackDetected() {
      return portScanDetected || hostDiscoveryDetected || synFloodDetected;
    }

    public String getAttackDescription() {
      if (portScanDetected) {
        return "Port scanning detected";
      } else if (hostDiscoveryDetected) {
        return "Host discovery detected";
      } else if (synFloodDetected) {
        return "SYN flood detected";
      }
      return "Unknown scanning activity detected";
    }

    public void setPortScanDetected(boolean detected) {
      this.portScanDetected = detected;
    }

    public void setHostDiscoveryDetected(boolean detected) {
      this.hostDiscoveryDetected = detected;
    }

    public void setSynFloodDetected(boolean detected) {
      this.synFloodDetected = detected;
    }
  }

  private static class Threshold {
    private final int value;

    public Threshold(int value) {
      this.value = value;
    }

    public int getValue() {
      return value;
    }
  }
}
