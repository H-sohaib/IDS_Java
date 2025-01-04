package com.ids.services;

// Inner class to hold packet information
class PacketInfo {
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
}