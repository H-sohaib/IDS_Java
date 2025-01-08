package com.ids.core;

// Inner class to hold packet information
public class PacketInfo {
  String sourceIp;
  String destinationIp;
  int sourcePort;
  int destinationPort;
  String protocol;
  long packetSize;

  PacketInfo(String sourceIp, String destinationIp, int sourcePort, int destinationPort, String protocol,
      long packetSize) {
    this.sourceIp = sourceIp;
    this.destinationIp = destinationIp;
    this.sourcePort = sourcePort;
    this.destinationPort = destinationPort;
    this.protocol = protocol;
    this.packetSize = packetSize;
  }

  public String getSourceIp() {
    return sourceIp;
  }

  public String getDestinationIp() {
    return destinationIp;
  }

  public int getSourcePort() {
    return sourcePort;
  }

  public int getDestinationPort() {
    return destinationPort;
  }

  public String getProtocol() {
    return protocol;
  }

  public long getPacketSize() {
    return packetSize;
  }
}