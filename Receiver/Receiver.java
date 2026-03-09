import java.net.*;
import java.io.*;
import java.util.*;

/**
 * CP372 A2 - DS-FTP Receiver
 * java Receiver <sender_ip> <sender_ack_port> <rcv_data_port> <output_file> <RN>
 * Uses starter DSPacket.java and ChaosEngine.java (unchanged).
 */
public class Receiver {

    private static final int MOD = 128;

    public static void main(String[] args) {
        if (args.length != 5) {
            System.out.println("Usage: java Receiver <sender_ip> <sender_ack_port> <rcv_data_port> <output_file> <RN>");
            return;
        }

        final String sndIP = args[0];
        final int sndAckPort = Integer.parseInt(args[1]);
        final int rcvDataPort = Integer.parseInt(args[2]);
        final String outputFile = args[3];
        final int RN = Integer.parseInt(args[4]);
        final int windowSize = 128; // Sender does not send window size ?

        DatagramSocket socket = null;
        FileOutputStream fileOut = null;

        try {
            socket = new DatagramSocket(rcvDataPort); // Start listening on rcvDataPort 
            InetAddress senderAddress = InetAddress.getByName(sndIP);

            fileOut = new FileOutputStream(outputFile);

            byte[] buf = new byte[128];
            DatagramPacket udpPacket = new DatagramPacket(buf, buf.length);

            int expectedSeq = 1;
            int lastDelivered = 0;
            int packets = 0; // Number of packages received

            Map<Integer, DSPacket> buffer = new HashMap<>();

            System.out.println("Receiver listening on port " + rcvDataPort);

            while (true) {
                socket.receive(udpPacket);
                ++ packets;

                DSPacket pkt = new DSPacket(udpPacket.getData());

                int type = pkt.getType();
                int seq = pkt.getSeqNum();
                boolean dropped = ChaosEngine.shouldDrop(packets, RN);
                

                if (type == 0) {    // Receive SOT handshake
                    System.out.println("Received SOT handshake");
                    DSPacket ack = new DSPacket((byte)2, 0, new byte[0]);
                    System.out.println("Send ACK 0 - SOT");
                    sendAck(socket, senderAddress, sndAckPort, sndIP, sndAckPort, ack, dropped);
                }
                else if (type == 1) { // Receive DATA 
                    System.out.println("Received seq#:" + seq);
                    if (seq == expectedSeq) { // In-order DATA
                        byte[] data = pkt.getPayload();
                        fileOut.write(data, 0, pkt.getLength());
                        lastDelivered = seq;
                        expectedSeq = (lastDelivered + 1) % 128;

                        DSPacket currPacket= buffer.get(expectedSeq);
                        while (currPacket != null) { // Move the receiving window
                            lastDelivered = expectedSeq;
                            expectedSeq = (lastDelivered + 1) % 128;

                            data = currPacket.getPayload();
                            fileOut.write(data, 0, pkt.getLength()); 

                            buffer.remove(lastDelivered);
                            currPacket = buffer.get(expectedSeq);
                        }
                    }
                    else if (seq > expectedSeq) { // Out-of-order DATA
                        if (lastDelivered < seq && seq <= lastDelivered + windowSize) { // Buffered if in window
                            if (!buffer.containsKey(seq)) {
                                buffer.put(seq, pkt);
                            }
                        }
                    }
                    else {
                        System.out.println("Received duplicate seq#:" + seq);
                    }
                    // Ignore (seq < expectedSeq) [duplicate]

                    DSPacket ack = new DSPacket((byte)2, lastDelivered, new byte[0]);
                    System.out.println("Send Cummulative Ack" + lastDelivered);
                    sendAck(socket, senderAddress, sndAckPort, sndIP, sndAckPort, ack, dropped);
                }
                else if (type == 3) {  // Receive EOT
                    System.out.println("Received EOT");
                    DSPacket ack = new DSPacket((byte)2, seq, new byte[0]);
                    System.out.println("Send ACK 0 - EOT");
                    sendAck(socket, senderAddress, sndAckPort, sndIP, sndAckPort, ack, dropped);
                    
                    break;
                }
        
            }

            System.out.println("File transfer complete!");
        }
        catch (Exception e) {
            e.printStackTrace();
        }   
        finally {
            try {
                if (fileOut != null) {
                    fileOut.close();
                }
            } 
            catch (IOException e) {
                e.printStackTrace();
            }

            if (socket != null) {
                socket.close();
            }
        }
    }

    // Send Ack
    private static void sendAck(DatagramSocket socket, InetAddress adr, int port, String sndIP, int sndAckPort, DSPacket pkt, boolean drop) 
            throws Exception{
        if (! drop) {
            DatagramPacket sndpkt = new DatagramPacket(pkt.toBytes(), 128, adr, port);
            socket.send(sndpkt);
        }
        else {
            System.out.println("ACK dropped!");
        }
    }
    
}
