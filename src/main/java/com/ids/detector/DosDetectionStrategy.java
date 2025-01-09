package com.ids.detector;

import com.ids.core.PacketInfo;
import com.ids.utils.Alert;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;

public class DosDetectionStrategy implements AttackDetectionStrategy {

  private static final Logger logger = Logger.getLogger(DosDetectionStrategy.class.getName());

  private static final int PACKET_THRESHOLD = 1000; // Threshold per minute to flag as DoS
  private static final long TIME_WINDOW = 60 * 1000; // Time window in milliseconds (1 minute)

  private final Map<String, TrafficStats> ipTrafficMap = new ConcurrentHashMap<>();

  @Override
  public void analyzePacket(PacketInfo packetInfo) {
    String sourceIp = packetInfo.getSourceIp();
    long currentTime = System.currentTimeMillis();

    // Get or initialize traffic stats for the source IP
    TrafficStats stats = ipTrafficMap.computeIfAbsent(sourceIp, ip -> new TrafficStats(currentTime));

    // Update traffic stats
    stats.incrementPacketCount();
    stats.updateLastSeen(currentTime);

    // Log traffic activity
    logger.fine("Packet received from IP: " + sourceIp + " | Total Packets: " + stats.getPacketCount());

    // Check for DoS attack within the time window
    if (stats.getPacketCount() > PACKET_THRESHOLD &&
        (currentTime - stats.getFirstSeen()) <= TIME_WINDOW) {
      if (!stats.isDosDetected()) {
        stats.setDosDetected(true);
        logger.warning("Potential DoS attack detected from IP: " + sourceIp);
      }
    }

    // Reset stats if the time window has passed
    if ((currentTime - stats.getLastSeen()) > TIME_WINDOW) {
      stats.reset(currentTime); // Reset stats and update firstSeen to the current time
      logger.fine("Resetting traffic stats for IP: " + sourceIp);
    }
  }

  @Override
  public boolean isAttackDetected() {
    return ipTrafficMap.values().stream().anyMatch(TrafficStats::isDosDetected);
  }

  @Override
  public String getAttackDescription() {
    return ipTrafficMap.entrySet().stream()
        .filter(entry -> entry.getValue().isDosDetected())
        .map(entry -> "Potential DoS attack detected from IP: " + entry.getKey())
        .findFirst()
        .orElse("No DoS attack detected");
  }

  @Override
  public Alert generateAlert() {
    if (isAttackDetected()) {
      String attackDescription = getAttackDescription();
      return new Alert("DoS Attack", attackDescription);
    }
    return null;
  }

  private static class TrafficStats {
    private int packetCount;
    private long firstSeen;
    private long lastSeen;
    private boolean dosDetected;

    public TrafficStats(long firstSeen) {
      this.firstSeen = firstSeen;
      this.lastSeen = firstSeen;
    }

    public void incrementPacketCount() {
      packetCount++;
    }

    public void updateLastSeen(long currentTime) {
      lastSeen = currentTime;
    }

    public void reset(long currentTime) {
      packetCount = 0;
      dosDetected = false;
      firstSeen = currentTime;
      logger.fine("Traffic stats reset for IP. New firstSeen: " + currentTime);
    }

    public int getPacketCount() {
      return packetCount;
    }

    public long getFirstSeen() {
      return firstSeen;
    }

    public long getLastSeen() {
      return lastSeen;
    }

    public boolean isDosDetected() {
      return dosDetected;
    }

    public void setDosDetected(boolean detected) {
      this.dosDetected = detected;
    }
  }
}
