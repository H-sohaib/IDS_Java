package com.ids.services;

import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV6Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;

import java.util.*;

public class ConnectionAnalyzer {

  // Map to track active connections
  private final Map<String, Connection> activeConnections = new HashMap<>();

  // Analyze a captured packet
  public void analyzePacket(Packet packet) {

    // Extract packet information
    PacketInfo packetInfo = extractPacketInfo(packet);

    // Create a unique key for the connection
    String connectionKey = String.format("%s:%d-%s:%d", packetInfo.sourceIp, packetInfo.sourcePort,
        packetInfo.destinationIp, packetInfo.destinationPort);

    // Update or create a new connection entry
    Connection connection = activeConnections.computeIfAbsent(
        connectionKey,
        key -> new Connection(packetInfo.sourceIp, packetInfo.destinationIp, packetInfo.sourcePort,
            packetInfo.destinationPort, packetInfo.protocol));
    connection.update(packetInfo.packetSize);
  }

  // Get all active connections
  public Collection<Connection> getActiveConnections() {
    return activeConnections.values();
  }

  // Clean up inactive connections (optional, based on timeout or inactivity)
  public void cleanupInactiveConnections(long timeout) {
    long currentTime = System.currentTimeMillis();
    activeConnections.entrySet().removeIf(entry -> (currentTime - entry.getValue().endTime) > timeout);
  }

  // Start analyzing captured packets
  public void startAnalyzing(PacketCapture packetCapture, long cleanupTimeout, long analysisInterval) {
    new Thread(() -> {
      while (true) {
        for (Packet packet : packetCapture.getCapturedPackets()) {
          analyzePacket(packet);
        }

        // Optionally, clean up inactive connections
        cleanupInactiveConnections(cleanupTimeout);

        // Sleep for a while before the next analysis
        try {
          Thread.sleep(analysisInterval);
        } catch (InterruptedException e) {
          e.printStackTrace();
        }
      }
    }).start();
  }

  // Print active connections periodically
  public void printActiveConnections(long printInterval) {
    new Thread(() -> {
      while (true) {
        Collection<Connection> activeConnections = getActiveConnections();
        for (Connection connection : activeConnections) {
          System.out.println(connection);
        }

        // Sleep for a while before the next retrieval
        try {
          Thread.sleep(printInterval);
        } catch (InterruptedException e) {
          e.printStackTrace();
        }
      }
    }).start();
  }

  // Extract information from a packet
  private PacketInfo extractPacketInfo(Packet packet) {
    String sourceIp = "";
    String destinationIp = "";
    int sourcePort = 0;
    int destinationPort = 0;
    String protocol = "";
    long packetSize = packet.length();

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
      } else if (ipV6Packet.contains(UdpPacket.class)) {
        UdpPacket udpPacket = ipV6Packet.get(UdpPacket.class);
        UdpPacket.UdpHeader udpHeader = udpPacket.getHeader();
        sourcePort = udpHeader.getSrcPort().valueAsInt();
        destinationPort = udpHeader.getDstPort().valueAsInt();
      }
    }

    return new PacketInfo(sourceIp, destinationIp, sourcePort, destinationPort, protocol, packetSize);
  }
}