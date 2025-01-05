package com.ids.services;

public class Connection {
  private final String sourceIp;
  private final String destinationIp;
  private final int sourcePort;
  private final int destinationPort;
  private final String protocol;
  private long packetCount = 0;
  private long byteCount = 0;
  private long startTime;
  long endTime;

  public Connection(String sourceIp, String destinationIp, int sourcePort, int destinationPort, String protocol) {
    this.sourceIp = sourceIp;
    this.destinationIp = destinationIp;
    this.sourcePort = sourcePort;
    this.destinationPort = destinationPort;
    this.protocol = protocol;
    this.startTime = System.currentTimeMillis();
  }

  public void update(long packetSize) {
    this.packetCount++;
    this.byteCount += packetSize;
    this.endTime = System.currentTimeMillis();
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

  public long getPacketCount() {
    return packetCount;
  }

  public long getByteCount() {
    return byteCount;
  }

  public long getStartTime() {
    return startTime;
  }

  public long getEndTime() {
    return endTime;
  }

  public long getDuration() {
    return endTime - startTime;
  }

  @Override
  public String toString() {
    return String.format(
        "Connection [%s:%d -> %s:%d, Protocol: %s, Packets: %d, Bytes: %d, Duration: %d ms]",
        sourceIp, sourcePort, destinationIp, destinationPort, protocol, packetCount, byteCount, (endTime - startTime));
  }
}
