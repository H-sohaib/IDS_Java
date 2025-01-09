package com.ids.core;

import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV6Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;

public class PacketInfo {
  public String sourceIp;
  public String destinationIp;
  public int sourcePort;
  public int destinationPort;
  public String protocol;
  public long packetSize;
  public boolean syn;
  public boolean ack;

  public PacketInfo(Packet packet) {
    extractPacketInfo(packet);
  }

  // Extract information from a packet
  private void extractPacketInfo(Packet packet) {
    sourceIp = "";
    destinationIp = "";
    sourcePort = 0;
    destinationPort = 0;
    protocol = "";
    packetSize = packet.length();
    syn = false;
    ack = false;

    if (packet.contains(IpV4Packet.class)) {
      IpV4Packet ipV4Packet = packet.get(IpV4Packet.class);
      IpV4Packet.IpV4Header ipV4Header = ipV4Packet.getHeader();
      sourceIp = ipV4Header.getSrcAddr().getHostAddress();
      destinationIp = ipV4Header.getDstAddr().getHostAddress();
      protocol = ipV4Header.getProtocol().name();

      if (ipV4Packet.contains(TcpPacket.class)) {
        TcpPacket tcpPacket = ipV4Packet.get(TcpPacket.class);
        TcpPacket.TcpHeader tcpHeader = tcpPacket.getHeader();
        sourcePort = tcpHeader.getSrcPort().valueAsInt();
        destinationPort = tcpHeader.getDstPort().valueAsInt();
        syn = tcpHeader.getSyn();
        ack = tcpHeader.getAck();
      } else if (ipV4Packet.contains(UdpPacket.class)) {
        UdpPacket udpPacket = ipV4Packet.get(UdpPacket.class);
        UdpPacket.UdpHeader udpHeader = udpPacket.getHeader();
        sourcePort = udpHeader.getSrcPort().valueAsInt();
        destinationPort = udpHeader.getDstPort().valueAsInt();
      }
    } else if (packet.contains(IpV6Packet.class)) {
      IpV6Packet ipV6Packet = packet.get(IpV6Packet.class);
      IpV6Packet.IpV6Header ipV6Header = ipV6Packet.getHeader();
      sourceIp = ipV6Header.getSrcAddr().getHostAddress();
      destinationIp = ipV6Header.getDstAddr().getHostAddress();
      protocol = ipV6Header.getNextHeader().name();

      if (ipV6Packet.contains(TcpPacket.class)) {
        TcpPacket tcpPacket = ipV6Packet.get(TcpPacket.class);
        TcpPacket.TcpHeader tcpHeader = tcpPacket.getHeader();
        sourcePort = tcpHeader.getSrcPort().valueAsInt();
        destinationPort = tcpHeader.getDstPort().valueAsInt();
        syn = tcpHeader.getSyn();
        ack = tcpHeader.getAck();
      } else if (ipV6Packet.contains(UdpPacket.class)) {
        UdpPacket udpPacket = ipV6Packet.get(UdpPacket.class);
        UdpPacket.UdpHeader udpHeader = udpPacket.getHeader();
        sourcePort = udpHeader.getSrcPort().valueAsInt();
        destinationPort = udpHeader.getDstPort().valueAsInt();
      }
    }
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

  public boolean isSyn() {
    return syn;
  }

  public boolean isAck() {
    return ack;
  }
}