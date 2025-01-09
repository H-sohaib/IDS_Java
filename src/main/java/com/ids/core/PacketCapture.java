package com.ids.core;

import org.pcap4j.core.*;
import org.pcap4j.packet.IcmpV4CommonPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;

import java.io.IOException;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

public class PacketCapture {
  private PcapHandle handle;
  private PcapNetworkInterface networkInterface;
  private String captureFilter;
  private List<Packet> capturedPackets;
  private static final int MAX_PACKETS = 10000; // Limit the number of captured packets

  // Constructor
  public PacketCapture(PcapNetworkInterface networkInterface, String captureFilter) {
    this.networkInterface = networkInterface;
    this.captureFilter = captureFilter;
    this.capturedPackets = new CopyOnWriteArrayList<>();
  }

  public PacketCapture(PcapNetworkInterface networkInterface) {
    this(networkInterface, "");
  }

  // Start capture
  public void startCapture(String outputFilePath)
      throws PcapNativeException, NotOpenException, IOException {
    PcapHandle.Builder phb = new PcapHandle.Builder(networkInterface.getName())
        .snaplen(65536)
        .promiscuousMode(PcapNetworkInterface.PromiscuousMode.PROMISCUOUS)
        .timeoutMillis(10);

    if (true) {
      phb.timestampPrecision(PcapHandle.TimestampPrecision.NANO);
    }

    handle = phb.build();

    PcapDumper dumper = handle.dumpOpen(outputFilePath);

    new Thread(() -> {
      try {
        handle.loop(-1, (Packet packet) -> {
          if (capturedPackets.size() >= MAX_PACKETS) {
            capturedPackets.clear(); // Clear the list if it reaches the maximum size
          }
          capturedPackets.add(packet);
          try {
            dumper.dump(packet, handle.getTimestamp());
          } catch (NotOpenException e) {
            throw new RuntimeException(e);
          }
          // // Log packet information
          // System.out.println("Captured packet: " + packet);
          // if (packet.contains(TcpPacket.class)) {
          // System.out.println("Captured TCP packet: " + packet);
          // } else if (packet.contains(UdpPacket.class)) {
          // System.out.println("Captured UDP packet: " + packet);
          // } else if (packet.contains(IcmpV4CommonPacket.class)) {
          // System.out.println("Captured ICMP packet: " + packet);
          // } else {
          // System.out.println("Captured other packet: " + packet);
          // }
          // Introduce a small delay to throttle packet capture
          // try {
          // Thread.sleep(10);
          // } catch (InterruptedException e) {
          // Thread.currentThread().interrupt();
          // }
        });
      } catch (InterruptedException | PcapNativeException | NotOpenException e) {
        e.printStackTrace();
      } finally {
        dumper.close();
        handle.close();
      }
    }).start();
  }

  // Stop capture
  public void stopCapture() throws NotOpenException {
    if (handle != null)
      handle.breakLoop();
  }

  // Packet handler
  private void packetHandler(Packet packet) {
    capturedPackets.add(packet);
    // Pass to listeners or analyzers if needed
  }

  // Get captured packets
  public List<Packet> getCapturedPackets() {
    return capturedPackets;
  }
}
