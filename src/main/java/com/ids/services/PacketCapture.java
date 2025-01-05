package com.ids.services;

import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;

import java.io.IOException;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

public class PacketCapture {
  private PcapHandle handle;
  private PcapNetworkInterface networkInterface;
  private String captureFilter;
  private List<Packet> capturedPackets;

  // Constructor
  public PacketCapture(PcapNetworkInterface networkInterface, String captureFilter) {
    this.networkInterface = networkInterface;
    this.captureFilter = captureFilter;
    this.capturedPackets = new CopyOnWriteArrayList<>();
  }

  public PacketCapture(PcapNetworkInterface networkInterface) {
    this.networkInterface = networkInterface;
    this.captureFilter = "";
    this.capturedPackets = new CopyOnWriteArrayList<>();
  }

  // Start capture
  public void startCapture(String outputFilePath) throws PcapNativeException, NotOpenException, IOException {
    handle = networkInterface.openLive(
        65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10);

    handle.setFilter(captureFilter, BpfProgram.BpfCompileMode.OPTIMIZE); // Empty filter to capture all traffic

    PcapDumper dumper = handle.dumpOpen(outputFilePath);

    new Thread(() -> {
      try {
        handle.loop(-1, (Packet packet) -> {
          capturedPackets.add(packet);
          try {
            dumper.dump(packet, handle.getTimestamp());
          } catch (NotOpenException e) {
            throw new RuntimeException(e);
          }
          // System.out.println(packet); // Print packet to terminal
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
