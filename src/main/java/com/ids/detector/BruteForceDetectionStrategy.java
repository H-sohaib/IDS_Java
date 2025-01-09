package com.ids.detector;

import com.ids.core.PacketInfo;
import com.ids.utils.Alert;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;

public class BruteForceDetectionStrategy implements AttackDetectionStrategy {
  private static final Logger logger = Logger.getLogger(BruteForceDetectionStrategy.class.getName());

  private static final int ATTEMPT_THRESHOLD = 10; // Max login attempts allowed per minute
  private static final long TIME_WINDOW = 60 * 1000; // Time window in milliseconds (1 minute)

  private final Map<String, LoginAttemptStats> loginAttemptMap = new ConcurrentHashMap<>();

  @Override
  public void analyzePacket(PacketInfo packetInfo) {
    String sourceIp = packetInfo.getSourceIp();
    int destinationPort = packetInfo.getDestinationPort();
    String protocol = packetInfo.getProtocol();
    long currentTime = System.currentTimeMillis();

    // Check if the packet corresponds to a login-related protocol (e.g., SSH, HTTP,
    // RDP)
    if (isLoginProtocol(destinationPort, protocol)) {
      // Get or initialize login attempt stats for the source IP
      LoginAttemptStats stats = loginAttemptMap.computeIfAbsent(sourceIp, ip -> new LoginAttemptStats(currentTime));

      // Update login attempt stats
      stats.incrementAttemptCount();
      stats.updateLastSeen(currentTime);

      // Log the login attempt
      logger.fine("Login attempt from IP: " + sourceIp + " | Attempts: " + stats.getAttemptCount());

      // Check for brute force attack within the time window
      if (stats.getAttemptCount() > ATTEMPT_THRESHOLD &&
          (currentTime - stats.getFirstSeen()) <= TIME_WINDOW) {
        if (!stats.isBruteForceDetected()) {
          stats.setBruteForceDetected(true);
          logger.warning("Brute force attack detected from IP: " + sourceIp);
        }
      }

      // Reset stats if the time window has passed
      if ((currentTime - stats.getLastSeen()) > TIME_WINDOW) {
        stats.reset(currentTime); // Reset stats and update firstSeen to the current time
        logger.fine("Resetting login attempts for IP: " + sourceIp);
      }
    }
  }

  @Override
  public boolean isAttackDetected() {
    return loginAttemptMap.values().stream().anyMatch(LoginAttemptStats::isBruteForceDetected);
  }

  @Override
  public String getAttackDescription() {
    return loginAttemptMap.entrySet().stream()
        .filter(entry -> entry.getValue().isBruteForceDetected())
        .map(entry -> "Brute force detected from IP: " + entry.getKey())
        .findFirst()
        .orElse("No brute force attack detected");
  }

  @Override
  public Alert generateAlert() {
    if (isAttackDetected()) {
      String attackDescription = getAttackDescription();
      return new Alert("Brute Force Attack", attackDescription);
    }
    return null;
  }

  private boolean isLoginProtocol(int port, String protocol) {
    // Check if the port corresponds to common login services
    return (protocol.equals("TCP") && (port == 22 || port == 21 || port == 3389 || port == 80 || port == 443));
    // SSH (22), FTP (21), RDP (3389), HTTP (80), HTTPS (443)
  }

  private static class LoginAttemptStats {
    private int attemptCount;
    private long firstSeen;
    private long lastSeen;
    private boolean bruteForceDetected;

    public LoginAttemptStats(long firstSeen) {
      this.firstSeen = firstSeen;
      this.lastSeen = firstSeen;
    }

    public void incrementAttemptCount() {
      attemptCount++;
    }

    public void updateLastSeen(long currentTime) {
      lastSeen = currentTime;
    }

    public void reset(long currentTime) {
      attemptCount = 0;
      bruteForceDetected = false;
      firstSeen = currentTime;
      logger.fine("Login attempts reset for IP. New firstSeen: " + currentTime);
    }

    public int getAttemptCount() {
      return attemptCount;
    }

    public long getFirstSeen() {
      return firstSeen;
    }

    public long getLastSeen() {
      return lastSeen;
    }

    public boolean isBruteForceDetected() {
      return bruteForceDetected;
    }

    public void setBruteForceDetected(boolean detected) {
      this.bruteForceDetected = detected;
    }
  }
}
