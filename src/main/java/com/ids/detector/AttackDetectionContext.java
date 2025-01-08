package com.ids.detector;

import com.ids.core.PacketInfo;
import com.ids.utils.Alert;

import java.util.ArrayList;
import java.util.List;

public class AttackDetectionContext {
  private List<AttackDetectionStrategy> strategies = new ArrayList<>();

  public void addStrategy(AttackDetectionStrategy strategy) {
    strategies.add(strategy);
  }

  public void analyzePacket(PacketInfo packetInfo) {
    for (AttackDetectionStrategy strategy : strategies) {
      strategy.analyzePacket(packetInfo);
    }
  }

  public List<Alert> generateAlerts() {
    List<Alert> alerts = new ArrayList<>();
    for (AttackDetectionStrategy strategy : strategies) {
      if (strategy.isAttackDetected()) {
        Alert alert = strategy.generateAlert();
        if (alert != null) {
          alerts.add(alert);
        }
      }
    }
    return alerts;
  }
}