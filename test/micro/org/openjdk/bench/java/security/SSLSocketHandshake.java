/*
 * Copyright (C) 2025, THL A29 Limited, a Tencent company. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 * 
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 */

package org.openjdk.bench.java.security;

import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Warmup;
import org.openjdk.jmh.annotations.TearDown;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.security.KeyStore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.CountDownLatch;

/**
 * Benchmark the performance of SSL/TLS handshakes using SSLSocket.
 * Supports TLSv1.2 and TLSv1.3. Optionally allows specifying cipher suites.
 * Client and server communicate over loopback address.
 */
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.SECONDS)
@State(Scope.Benchmark)
@Warmup(iterations = 5, time = 5)
@Measurement(iterations = 5, time = 5)
@Fork(value = 3)
public class SSLSocketHandshake {

    static final InetAddress address = InetAddress.getLoopbackAddress();

    /**
     * TLS protocol version to use for the handshake. Supported: TLSv1.2, TLSv1.3
     */
    @Param({"TLSv1.2", "TLSv1.3"})
    public String protocol;

    private SSLServerSocket serverSocket;
    private Thread serverThread;
    private volatile boolean running;
    private int serverPort;
    private SSLContext sslContext;
    private SSLSocket clientSocket;
    private CountDownLatch serverReadyLatch;

    @Setup(Level.Trial)
    public void setupServer() throws Exception {
        KeyStore ks = TestCertificates.getKeyStore();
        KeyStore ts = TestCertificates.getTrustStore();

        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, new char[0]);

        TrustManagerFactory tmf = TrustManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        tmf.init(ts);

        sslContext = SSLContext.getInstance(protocol);
        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

        serverSocket = (SSLServerSocket) sslContext.getServerSocketFactory().createServerSocket(0);
        serverPort = serverSocket.getLocalPort();
        running = true;
        serverReadyLatch = new CountDownLatch(1);
        
        serverThread = new Thread(() -> {
            try {
                serverReadyLatch.countDown(); // Mark server as ready
                while (running) {
                    try {
                        // Use try-with-resources to ensure the socket is closed automatically
                        try (SSLSocket s = (SSLSocket) serverSocket.accept()) {
                            s.setUseClientMode(false);
                            // Explicitly set the cipher suites
                            String[] cipherSuites = getCipherSuites();
                            s.setEnabledCipherSuites(cipherSuites);
                            // Trigger handshake by exchanging data (no explicit startHandshake)
                            s.getInputStream().read();
                            s.getOutputStream().write(1);
                        }
                    } catch (Exception e) {
                        if (running) {
                            System.err.println("Server handshake failed: " + e.getMessage());
                        }
                    }
                }
            } catch (Exception e) {
                if (running) {
                    System.err.println("Server thread error: " + e.getMessage());
                    e.printStackTrace();
                }
                running = false;
            }
        });
        serverThread.setDaemon(true);
        serverThread.start();
        
        // Wait for server thread to enter accept
        serverReadyLatch.await();
        // Optional: sleep 20ms to ensure accept is blocked
        Thread.sleep(20);
    }

    @Setup(Level.Invocation)
    public void setupClient() throws Exception {
        SSLSocketFactory factory = sslContext.getSocketFactory();
        int retries = 5;
        Exception lastException = null;
        
        while (retries > 0) {
            try {
                clientSocket = (SSLSocket) factory.createSocket(address, serverPort);
                clientSocket.setUseClientMode(true);
                // Explicitly set the cipher suites
                String[] cipherSuites = getCipherSuites();
                clientSocket.setEnabledCipherSuites(cipherSuites);
                return; // Connection successful, return directly
            } catch (Exception e) {
                // Ensure the socket is closed before retrying to avoid resource leak
                if (clientSocket != null) {
                    try {
                        clientSocket.close();
                    } catch (IOException ioex) {
                        e.addSuppressed(ioex);
                    } finally {
                        clientSocket = null;
                    }
                }
                lastException = e;
                retries--;
                if (retries > 0) {
                    Thread.sleep(50); // Wait 50ms before retry
                }
            }
        }
        // All retries failed; lastException is guaranteed to be non-null here.
        throw lastException;
    }

    @Benchmark
    public void handshake() throws Exception {
        // Trigger handshake by exchanging data. The actual handshake is
        // initiated on the first I/O operation.
        clientSocket.getOutputStream().write(1);
        clientSocket.getInputStream().read();
    }

    @TearDown(Level.Invocation)
    public void tearDownClient() throws IOException {
        // Close the client socket after each benchmark invocation to avoid
        // including socket close I/O in the benchmark measurement.
        if (clientSocket != null) {
            clientSocket.close();
            clientSocket = null;
        }
    }

    @TearDown(Level.Trial)
    public void tearDownServer() throws Exception {
        running = false;
        if (serverSocket != null) {
            serverSocket.close();
        }
        if (serverThread != null) {
            serverThread.join(1000); // Wait up to 1 second
        }
    }

    /**
     * Returns cipher suites for the selected protocol.
     */
    private String[] getCipherSuites() {
        if ("TLSv1.2".equals(protocol)) {
            // Use a single cipher suite for TLSv1.2
            return new String[]{
                "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
            };
        } else {
            // TLSv1.3 cipher suites
            return new String[]{"TLS_AES_128_GCM_SHA256"};
        }
    }
} 