import java.net.*;
import java.io.*;
import java.util.*;

/**
 * CP372 A2 - DS-FTP Sender
 * Stop-and-Wait: java Sender <rcv_ip> <rcv_data_port> <sender_ack_port> <input_file> <timeout_ms>
 * Go-Back-N: java Sender <rcv_ip> <rcv_data_port> <sender_ack_port> <input_file> <timeout_ms> <window_size>
 * Uses starter DSPacket.java and ChaosEngine.java (unchanged).
 */
public class Sender {

    private static final int MOD = 128;

    public static void main(String[] args) {
        if (args.length != 5 && args.length != 6) {
            System.out.println("Usage: java Sender <rcv_ip> <rcv_data_port> <sender_ack_port> <input_file> <timeout_ms> [window_size]");
            return;
        }

        final String rcvIp = args[0];
        final int rcvDataPort = Integer.parseInt(args[1]);
        final int senderAckPort = Integer.parseInt(args[2]);
        final String inputFile = args[3];
        final int timeoutMs = Integer.parseInt(args[4]);

        final boolean useGBN = (args.length == 6);
        final int windowSize = useGBN ? Integer.parseInt(args[5]) : 0;

        if (useGBN) {
            if (windowSize <= 0 || windowSize > MOD || (windowSize % 4 != 0)) {
                System.out.println("Invalid window_size. Must be a multiple of 4 and <= 128.");
                return;
            }
        }

        DatagramSocket sendSocket = null;
        DatagramSocket ackSocket = null;

        long startTimeNs = 0L;

        try {
            InetAddress rcvAddr = InetAddress.getByName(rcvIp);

            sendSocket = new DatagramSocket();                 // ephemeral
            ackSocket = new DatagramSocket(senderAckPort);     // listen on this port
            ackSocket.setSoTimeout(timeoutMs);

            // Start timing from first SOT send attempt
            startTimeNs = System.nanoTime();

            // Phase 1: Handshake (SOT -> ACK0)
            doHandshake(sendSocket, ackSocket, rcvAddr, rcvDataPort);

            // Read file bytes (raw binary)
            byte[] fileBytes = readFileBytes(inputFile);

            // Phase 2: Data transfer
            if (!useGBN) {
                stopAndWaitTransfer(sendSocket, ackSocket, rcvAddr, rcvDataPort, fileBytes);
            } else {
                goBackNTransfer(sendSocket, ackSocket, rcvAddr, rcvDataPort, fileBytes, windowSize);
            }

            // Phase 3: Teardown (EOT -> ACK)
            int eotSeq = computeEotSeq(fileBytes);
            sendEOTAndWaitAck(sendSocket, ackSocket, rcvAddr, rcvDataPort, eotSeq);

            long endTimeNs = System.nanoTime();
            double seconds = (endTimeNs - startTimeNs) / 1_000_000_000.0;
            System.out.printf("Total Transmission Time: %.2f seconds%n", seconds);

        } catch (CriticalFailure cf) {
            // message:
            System.out.println("Unable to transfer file.");
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            if (sendSocket != null) sendSocket.close();
            if (ackSocket != null) ackSocket.close();
        }
    }

    // Phase 1: Handshake
    private static void doHandshake(DatagramSocket sendSocket,
                                    DatagramSocket ackSocket,
                                    InetAddress rcvAddr,
                                    int rcvDataPort) throws Exception {

        DSPacket sot = new DSPacket(DSPacket.TYPE_SOT, 0, null);
        byte[] sotBytes = sot.toBytes();

        int timeoutStreak = 0;

        while (true) {
            send128(sendSocket, sotBytes, rcvAddr, rcvDataPort);
            log("SENT SOT seq=0");

            try {
                DSPacket ack = recv128AsPacket(ackSocket);
                if (ack.getType() == DSPacket.TYPE_ACK && ack.getSeqNum() == 0) {
                    log("RCV ACK seq=0 (SOT)");
                    return;
                } else {
                    log("IGNORED packet while waiting SOT ACK: type=" + ack.getType() + " seq=" + ack.getSeqNum());
                }
            } catch (SocketTimeoutException ste) {
                timeoutStreak++;
                log("TIMEOUT waiting SOT ACK (" + timeoutStreak + "/3)");
                if (timeoutStreak >= 3) throw new CriticalFailure();
            }
        }
    }

    // Stop-and-Wait Transfer
    private static void stopAndWaitTransfer(DatagramSocket sendSocket,
                                            DatagramSocket ackSocket,
                                            InetAddress rcvAddr,
                                            int rcvDataPort,
                                            byte[] fileBytes) throws Exception {

        // Empty file case: send EOT seq=1 immediately after handshake (handled by computeEotSeq + EOT)
        if (fileBytes.length == 0) {
            log("Empty file: no DATA packets sent.");
            return;
        }

        int seq = 1;
        int offset = 0;

        while (offset < fileBytes.length) {
            int len = Math.min(DSPacket.MAX_PAYLOAD_SIZE, fileBytes.length - offset);
            byte[] payload = Arrays.copyOfRange(fileBytes, offset, offset + len);

            DSPacket dataPkt = new DSPacket(DSPacket.TYPE_DATA, seq, payload);
            byte[] dataBytes = dataPkt.toBytes();

            int timeoutStreak = 0;

            while (true) {
                send128(sendSocket, dataBytes, rcvAddr, rcvDataPort);
                log("SENT DATA seq=" + seq + " len=" + len);

                try {
                    DSPacket ack = recv128AsPacket(ackSocket);
                    if (ack.getType() == DSPacket.TYPE_ACK && ack.getSeqNum() == seq) {
                        log("RCV ACK seq=" + seq);
                        break;
                    } else {
                        log("IGNORED packet: type=" + ack.getType() + " seq=" + ack.getSeqNum());
                    }
                } catch (SocketTimeoutException ste) {
                    timeoutStreak++;
                    log("TIMEOUT DATA seq=" + seq + " (" + timeoutStreak + "/3) -> retransmit");
                    if (timeoutStreak >= 3) throw new CriticalFailure();
                }
            }

            offset += len;
            seq = (seq + 1) % MOD;
        }
    }

    // Go-Back-N Transfer
    private static void goBackNTransfer(DatagramSocket sendSocket,
                                        DatagramSocket ackSocket,
                                        InetAddress rcvAddr,
                                        int rcvDataPort,
                                        byte[] fileBytes,
                                        int windowSize) throws Exception {

        List<DSPacket> packets = buildDataPackets(fileBytes);

        // Empty file case: no DATA; receiver expects EOT seq=1
        if (packets.isEmpty()) {
            log("Empty file: no DATA packets sent.");
            return;
        }

        int baseIndex = 0;         // oldest unACKed packet (by list index)
        int nextIndex = 0;         // next packet to send (by list index)

        // Timeout streak applies to the same baseIndex without progress
        int timeoutStreak = 0;
        int lastBaseIndex = 0;

        while (baseIndex < packets.size()) {

            // Send new packets while window not full
            while (nextIndex < packets.size() && (nextIndex - baseIndex) < windowSize) {

                int remaining = packets.size() - nextIndex;
                int windowRemaining = windowSize - (nextIndex - baseIndex);

                // If we can send a full group of 4 as "new sends", apply ChaosEngine permutation
                if (remaining >= 4 && windowRemaining >= 4) {
                    List<DSPacket> group = new ArrayList<>(4);
                    group.add(packets.get(nextIndex));
                    group.add(packets.get(nextIndex + 1));
                    group.add(packets.get(nextIndex + 2));
                    group.add(packets.get(nextIndex + 3));

                    List<DSPacket> permuted = ChaosEngine.permutePackets(group);
                    for (DSPacket p : permuted) {
                        send128(sendSocket, p.toBytes(), rcvAddr, rcvDataPort);
                        log("SENT DATA seq=" + p.getSeqNum() + " len=" + p.getLength());
                    }

                    nextIndex += 4;
                } else {
                    DSPacket p = packets.get(nextIndex);
                    send128(sendSocket, p.toBytes(), rcvAddr, rcvDataPort);
                    log("SENT DATA seq=" + p.getSeqNum() + " len=" + p.getLength());
                    nextIndex += 1;
                }
            }

            // Wait for ACK to move baseIndex
            try {
                DSPacket ack = recv128AsPacket(ackSocket);
                if (ack.getType() != DSPacket.TYPE_ACK) {
                    log("IGNORED non-ACK packet: type=" + ack.getType() + " seq=" + ack.getSeqNum());
                    continue;
                }

                int ackSeq = ack.getSeqNum();
                log("RCV ACK seq=" + ackSeq + " (cumulative)");

                // Find the packet with seq == ackSeq in the current in-flight range [baseIndex, nextIndex)
                int foundIndex = findSeqInRange(packets, baseIndex, nextIndex, ackSeq);

                if (foundIndex >= baseIndex) {
                    int newBase = foundIndex + 1;
                    if (newBase > baseIndex) {
                        baseIndex = newBase;
                        log("WINDOW ADVANCED -> baseIndex=" + baseIndex + " nextIndex=" + nextIndex);
                        timeoutStreak = 0;          // progress happened
                        lastBaseIndex = baseIndex;  // update baseline
                    }
                } else {
                    // ACK doesn't advance base (duplicate/old); ignore for progress
                    log("ACK did not advance window (duplicate/old).");
                }

            } catch (SocketTimeoutException ste) {
                if (baseIndex == lastBaseIndex) {
                    timeoutStreak++;
                } else {
                    timeoutStreak = 1;
                    lastBaseIndex = baseIndex;
                }

                log("TIMEOUT at baseIndex=" + baseIndex + " (" + timeoutStreak + "/3) -> retransmit from base");

                if (timeoutStreak >= 3) throw new CriticalFailure();

                // Retransmit entire window from base in NORMAL order (safe & matches “retransmit from base”)
                for (int i = baseIndex; i < nextIndex && i < packets.size(); i++) {
                    DSPacket p = packets.get(i);
                    send128(sendSocket, p.toBytes(), rcvAddr, rcvDataPort);
                    log("RE-SENT DATA seq=" + p.getSeqNum() + " len=" + p.getLength());
                }
            }
        }
    }

    /**
     * Find index in [start, end) whose packet seq == targetSeq.
     * Returns -1 if not found.
     */
    private static int findSeqInRange(List<DSPacket> packets, int start, int end, int targetSeq) {
        int e = Math.min(end, packets.size());
        for (int i = start; i < e; i++) {
            if (packets.get(i).getSeqNum() == targetSeq) return i;
        }
        return -1;
    }

    // Phase 3: Teardown (EOT)
    private static void sendEOTAndWaitAck(DatagramSocket sendSocket,
                                         DatagramSocket ackSocket,
                                         InetAddress rcvAddr,
                                         int rcvDataPort,
                                         int eotSeq) throws Exception {

        DSPacket eot = new DSPacket(DSPacket.TYPE_EOT, eotSeq, null);
        byte[] eotBytes = eot.toBytes();

        int timeoutStreak = 0;

        while (true) {
            send128(sendSocket, eotBytes, rcvAddr, rcvDataPort);
            log("SENT EOT seq=" + eotSeq);

            try {
                DSPacket ack = recv128AsPacket(ackSocket);
                if (ack.getType() == DSPacket.TYPE_ACK && ack.getSeqNum() == eotSeq) {
                    log("RCV ACK seq=" + eotSeq + " (EOT)");
                    return;
                } else {
                    log("IGNORED packet while waiting EOT ACK: type=" + ack.getType() + " seq=" + ack.getSeqNum());
                }
            } catch (SocketTimeoutException ste) {
                timeoutStreak++;
                log("TIMEOUT waiting EOT ACK (" + timeoutStreak + "/3)");
                if (timeoutStreak >= 3) throw new CriticalFailure();
            }
        }
    }

    // Build DATA packets
    private static List<DSPacket> buildDataPackets(byte[] fileBytes) {
        List<DSPacket> list = new ArrayList<>();
        int seq = 1;
        int offset = 0;

        while (offset < fileBytes.length) {
            int len = Math.min(DSPacket.MAX_PAYLOAD_SIZE, fileBytes.length - offset);
            byte[] payload = Arrays.copyOfRange(fileBytes, offset, offset + len);

            DSPacket p = new DSPacket(DSPacket.TYPE_DATA, seq, payload);
            list.add(p);

            offset += len;
            seq = (seq + 1) % MOD;
        }

        return list;
    }

    private static int computeEotSeq(byte[] fileBytes) {
        // Empty file rule: EOT seq = 1
        if (fileBytes.length == 0) return 1;

        int dataCount = (fileBytes.length + DSPacket.MAX_PAYLOAD_SIZE - 1) / DSPacket.MAX_PAYLOAD_SIZE;
        int lastDataSeq = (1 + dataCount - 1) % MOD;
        return (lastDataSeq + 1) % MOD;
    }

    // UDP Helpers
    private static void send128(DatagramSocket sock, byte[] bytes, InetAddress addr, int port) throws IOException {
        if (bytes.length != DSPacket.MAX_PACKET_SIZE) {
            throw new IOException("Packet size not 128 bytes: " + bytes.length);
        }
        DatagramPacket dp = new DatagramPacket(bytes, bytes.length, addr, port);
        sock.send(dp);
    }

    private static DSPacket recv128AsPacket(DatagramSocket sock) throws IOException {
        byte[] buf = new byte[DSPacket.MAX_PACKET_SIZE];
        DatagramPacket dp = new DatagramPacket(buf, buf.length);
        sock.receive(dp);
        return new DSPacket(dp.getData());
    }

    // File IO
    private static byte[] readFileBytes(String path) throws IOException {
        File f = new File(path);
        if (!f.exists()) throw new FileNotFoundException("Input file not found: " + path);

        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
             InputStream in = new FileInputStream(f)) {
            byte[] buf = new byte[8192];
            int r;
            while ((r = in.read(buf)) != -1) bos.write(buf, 0, r);
            return bos.toByteArray();
        }
    }

    private static void log(String msg) {
        System.out.println(msg);
    }

    // Critical Failure (3 timeouts without progress)
    private static class CriticalFailure extends Exception { }
}
