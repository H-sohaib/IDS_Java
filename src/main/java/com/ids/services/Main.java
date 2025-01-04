package com.ids.services;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.util.NifSelector;

import java.io.IOException;

public class Main {
    public static void main(String[] args) throws IOException, NotOpenException, PcapNativeException {

        PcapNetworkInterface niterface = new NifSelector().selectNetworkInterface();
        System.out.println("Selected Interface : " + niterface.getDescription());

        // create a new PacketCapture object and start capturing packets
        PacketCapture packetCapture = new PacketCapture(niterface); // no filter
        packetCapture.startCapture("output.pcap");

        PacketCapture packetCapture2 = new PacketCapture(niterface , "tcp port 443" ); // no filter
        packetCapture.startCapture("output2.pcap");


    }

}