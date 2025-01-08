package com.ids.core;

public class PacketStatistic {
  private final String ip;
  private int incomingPackets;
  private int outgoingPackets;

  public PacketStatistic(String ip, int incomingPackets, int outgoingPackets) {
    this.ip = ip;
    this.incomingPackets = incomingPackets;
    this.outgoingPackets = outgoingPackets;
  }

  public String getIp() {
    return ip;
  }

  public int getIncomingPackets() {
    return incomingPackets;
  }

  public void setIncomingPackets(int incomingPackets) {
    this.incomingPackets = incomingPackets;
  }

  public int getOutgoingPackets() {
    return outgoingPackets;
  }

  public void setOutgoingPackets(int outgoingPackets) {
    this.outgoingPackets = outgoingPackets;
  }
}