# JAVA IDS Project

Pcap4j repo: [https://github.com/kaitoy/pcap4j](https://github.com/kaitoy/pcap4j)  
Pcap4j code examples: [https://github.com/kaitoy/pcap4j/blob/v1/pcap4j-sample/src/main/java/org/pcap4j/sample](https://github.com/kaitoy/pcap4j/blob/v1/pcap4j-sample/src/main/java/org/pcap4j/sample)

## Requirements

1. Maven will install the libraries for you (pcap4j).
2. Pcap4j requires installing [Npcap](https://npcap.com/) for Windows.
3. Add `%SystemRoot%\System32\Npcap\` to the system environment path.
4. Edit configuration and paste the following in VM options:
    ```
    -Dorg.pcap4j.core.pcapLibName=C:\Windows\System32\Npcap\wpcap.dll -Dorg.pcap4j.core.packetLibName=C:\Windows\System32\Npcap\Packet.dll -Djna.library.path=C:\Windows\System32\Npcap
    ```