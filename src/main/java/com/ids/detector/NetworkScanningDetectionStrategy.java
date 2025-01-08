package com.ids.detector;

import com.ids.core.PacketInfo;
import com.ids.utils.Alert;

import java.util.HashMap;
import java.util.Map;

public class NetworkScanningDetectionStrategy implements AttackDetectionStrategy {
  private static final int THRESHOLD = 100; // Example threshold for scanning detection
  private Map<String, Integer> ipCountMap = new HashMap<>();
  private boolean attackDetected = false;

  @Override
  public void analyzePacket(PacketInfo packetInfo) {
    String sourceIp = packetInfo.getSourceIp();
    ipCountMap.put(sourceIp, ipCountMap.getOrDefault(sourceIp, 0) + 1);

    if (ipCountMap.get(sourceIp) > THRESHOLD) {
      attackDetected = true;
    }
  }

  @Override
  public boolean isAttackDetected() {
    return attackDetected;
  }

  @Override
  public String getAttackDescription() {
    return "Network scanning detected from IP: " + ipCountMap.entrySet().stream()
        .filter(entry -> entry.getValue() > THRESHOLD)
        .map(Map.Entry::getKey)
        .findFirst()
        .orElse("Unknown");
  }

  @Override
  public Alert generateAlert() {
    if (isAttackDetected()) {
      return new Alert("Network Scanning", getAttackDescription());
    }
    return null;
  }
}