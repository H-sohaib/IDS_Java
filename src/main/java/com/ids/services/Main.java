package com.ids.services;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.util.NifSelector;

import java.io.IOException;

public class Main {
  public static void main(String[] args) throws IOException, NotOpenException, PcapNativeException {

    PcapNetworkInterface networkInterface = new NifSelector().selectNetworkInterface();
    System.out.println("Selected Interface : " + networkInterface.getDescription());

    // create a new PacketCapture object and start capturing packets
    PacketCapture packetCapture = new PacketCapture(networkInterface); // no filter
    ConnectionAnalyzer connectionAnalyzer = new ConnectionAnalyzer();

    packetCapture.startCapture("output.pcap");

    connectionAnalyzer.startAnalyzing(packetCapture, 60000, 1000); // 1 minute cleanup timeout, 1 second analysis

    // Print active connections periodically with custom print interval
    // connectionAnalyzer.printActiveConnections(5000); // 5 seconds print interval

    // Print packet statistics periodically with custom print interval
    connectionAnalyzer.printPacketStatistics(5000); // 5 seconds print interval
  }

}