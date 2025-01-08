package com.ids.core.core;

import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;
import org.pcap4j.util.NifSelector;

import java.io.IOException;

public class Trying {

    public static void main(String[] args) throws IOException, PcapNativeException, NotOpenException {
        PcapNetworkInterface netInterface =  new NifSelector().selectNetworkInterface();

        System.out.printf( "Selected Interface : '%s'", netInterface.getDescription());

        PcapHandle handle = netInterface.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10);

        handle.setFilter("", BpfProgram.BpfCompileMode.OPTIMIZE); // Empty filter to capture all traffic

        int packetCount = 0;
        while (true) {
            Packet packet = handle.getNextPacket();
            if (packet == null) {
                continue;
            }
            System.out.println("Packet " + ++packetCount + ": " + packet);
        }
    }
}
