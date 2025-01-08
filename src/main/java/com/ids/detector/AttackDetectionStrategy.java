package com.ids.detector;

import com.ids.core.PacketInfo;
import com.ids.utils.Alert;

public interface AttackDetectionStrategy {
  void analyzePacket(PacketInfo packetInfo);

  boolean isAttackDetected();

  String getAttackDescription();

  Alert generateAlert();
}