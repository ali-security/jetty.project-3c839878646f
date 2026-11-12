//
//  ========================================================================
//  Copyright (c) 1995-2017 Mort Bay Consulting Pty. Ltd.
//  ------------------------------------------------------------------------
//  All rights reserved. This program and the accompanying materials
//  are made available under the terms of the Eclipse Public License v1.0
//  and Apache License v2.0 which accompanies this distribution.
//
//      The Eclipse Public License is available at
//      http://www.eclipse.org/legal/epl-v10.html
//
//      The Apache License v2.0 is available at
//      http://www.opensource.org/licenses/apache2.0.php
//
//  You may elect to redistribute this code under either of these licenses.
//  ========================================================================
//

package org.eclipse.jetty.io;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Socket;
import java.net.SocketException;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSocket;

import org.eclipse.jetty.io.SelectorManager.ManagedSelector;
import org.eclipse.jetty.io.ssl.SslConnection;
import org.eclipse.jetty.toolchain.test.MavenTestingUtils;
import org.eclipse.jetty.util.BufferUtil;
import org.eclipse.jetty.util.FutureCallback;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.eclipse.jetty.util.thread.QueuedThreadPool;
import org.eclipse.jetty.util.thread.Scheduler;
import org.eclipse.jetty.util.thread.TimerScheduler;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;


public class SslConnectionTest
{
    private static SslContextFactory __sslCtxFactory=new SslContextFactory();
    private static ByteBufferPool __byteBufferPool = new LeakTrackingByteBufferPool(new MappedByteBufferPool.Tagged());

    protected volatile EndPoint _lastEndp;
    private volatile boolean _testFill=true;
    private volatile int _inputBufferSize=8*1024;
    private volatile FutureCallback _writeCallback;
    protected ServerSocketChannel _connector;
    final AtomicInteger _dispatches = new AtomicInteger();
    protected QueuedThreadPool _threadPool = new QueuedThreadPool()
    {
        @Override
        public void execute(Runnable job)
        {
            _dispatches.incrementAndGet();
            super.execute(job);
        }

    };
    protected Scheduler _scheduler = new TimerScheduler();
    protected SelectorManager _manager = new SelectorManager(_threadPool, _scheduler)
    {
        @Override
        public Connection newConnection(SocketChannel channel, EndPoint endpoint, Object attachment)
        {
            SSLEngine engine = __sslCtxFactory.newSSLEngine();
            engine.setUseClientMode(false);
            SslConnection sslConnection = new SslConnection(__byteBufferPool, getExecutor(), endpoint, engine);
            sslConnection.setRenegotiationAllowed(__sslCtxFactory.isRenegotiationAllowed());
            Connection appConnection = new TestConnection(sslConnection.getDecryptedEndPoint());
            sslConnection.getDecryptedEndPoint().setConnection(appConnection);
            return sslConnection;
        }

        @Override
        protected SelectChannelEndPoint newEndPoint(SocketChannel channel, ManagedSelector selectSet, SelectionKey selectionKey) throws IOException
        {
            SelectChannelEndPoint endp = new TestEP(channel,selectSet, selectionKey, getScheduler(), 60000);
            _lastEndp=endp;
            return endp;
        }
    };

    static final AtomicInteger __startBlocking = new AtomicInteger();
    static final AtomicInteger __blockFor = new AtomicInteger();
    private static class TestEP extends SelectChannelEndPoint
    {
       
        public TestEP(SocketChannel channel, ManagedSelector selector, SelectionKey key, Scheduler scheduler, long idleTimeout)
        {
            super(channel,selector,key,scheduler,idleTimeout);
        }

        @Override
        protected void onIncompleteFlush()
        {
            super.onIncompleteFlush();
        }
        

        @Override
        public boolean flush(ByteBuffer... buffers) throws IOException
        {
            if (__startBlocking.get()==0 || __startBlocking.decrementAndGet()==0)
            {
                if (__blockFor.get()>0 && __blockFor.getAndDecrement()>0)
                {
                    return false;
                }
            }
            String s=BufferUtil.toDetailString(buffers[0]);
            boolean flushed=super.flush(buffers);
            return flushed;
        }
    }
    

    @BeforeClass
    public static void initSslEngine() throws Exception
    {
        File keystore = MavenTestingUtils.getTestResourceFile("keystore");
        __sslCtxFactory.setKeyStorePath(keystore.getAbsolutePath());
        __sslCtxFactory.setKeyStorePassword("storepwd");
        __sslCtxFactory.setKeyManagerPassword("keypwd");
        __sslCtxFactory.start();
    }

    @Before
    public void startManager() throws Exception
    {
        _testFill=true;
        _inputBufferSize=8*1024;
        _writeCallback=null;
        _lastEndp=null;
        _connector = ServerSocketChannel.open();
        _connector.socket().bind(null);
        _threadPool.start();
        _scheduler.start();
        _manager.start();

    }

    @After
    public void stopManager() throws Exception
    {
        if (_lastEndp.isOpen())
            _lastEndp.close();
        _manager.stop();
        _scheduler.stop();
        _threadPool.stop();
        _connector.close();
    }

    public class TestConnection extends AbstractConnection
    {
        ByteBuffer _in = BufferUtil.allocate(_inputBufferSize);

        public TestConnection(EndPoint endp)
        {
            super(endp, _threadPool,true);
        }

        @Override
        public void onOpen()
        {
            super.onOpen();
            if (_testFill)
                fillInterested();
            else
            {
                getExecutor().execute(new Runnable()
                {

                    @Override
                    public void run()
                    {
                        getEndPoint().write(_writeCallback,BufferUtil.toBuffer("Hello Client"));
                    }
                });
            }
        }

        @Override
        public void onClose()
        {
            super.onClose();
        }

        @Override
        public synchronized void onFillable()
        {
            EndPoint endp = getEndPoint();
            try
            {
                boolean progress=true;
                while(progress)
                {
                    progress=false;

                    // Fill the input buffer with everything available
                    int filled=endp.fill(_in);
                    while (filled>0)
                    {
                        progress=true;
                        filled=endp.fill(_in);
                    }

                    // Write everything
                    int l=_in.remaining();
                    if (l>0)
                    {
                        FutureCallback blockingWrite= new FutureCallback();
                        endp.write(blockingWrite,_in);
                        blockingWrite.get();
                    }

                    // are we done?
                    if (endp.isInputShutdown())
                    {
                        endp.shutdownOutput();
                    }
                }
            }
            catch(InterruptedException|EofException e)
            {
                SelectChannelEndPoint.LOG.ignore(e);
            }
            catch(Exception e)
            {
                SelectChannelEndPoint.LOG.warn(e);
            }
            finally
            {
                if (endp.isOpen())
                    fillInterested();
            }
        }
    }
    protected Socket newClient() throws IOException
    {
        SSLSocket socket = __sslCtxFactory.newSslSocket();
        socket.connect(_connector.socket().getLocalSocketAddress());
        return socket;
    }

    @Test
    public void testHelloWorld() throws Exception
    {
        Socket client = newClient();
        client.setSoTimeout(60000);

        SocketChannel server = _connector.accept();
        server.configureBlocking(false);
        _manager.accept(server);

        client.getOutputStream().write("Hello".getBytes(StandardCharsets.UTF_8));
        byte[] buffer = new byte[1024];
        int len=client.getInputStream().read(buffer);
        Assert.assertEquals(5, len);
        Assert.assertEquals("Hello",new String(buffer,0,len,StandardCharsets.UTF_8));

        _dispatches.set(0);
        client.getOutputStream().write("World".getBytes(StandardCharsets.UTF_8));
        len=5;
        while(len>0)
            len-=client.getInputStream().read(buffer);
        Assert.assertEquals(1, _dispatches.get());

        client.close();
    }


    @Test
    public void testWriteOnConnect() throws Exception
    {
        _testFill=false;

        _writeCallback = new FutureCallback();
        Socket client = newClient();
        client.setSoTimeout(10000);

        SocketChannel server = _connector.accept();
        server.configureBlocking(false);
        _manager.accept(server);

        byte[] buffer = new byte[1024];
        int len=client.getInputStream().read(buffer);
        Assert.assertEquals("Hello Client",new String(buffer,0,len,StandardCharsets.UTF_8));
        Assert.assertEquals(null,_writeCallback.get(100,TimeUnit.MILLISECONDS));
        client.close();
    }
    


    @Test
    public void testBlockedWrite() throws Exception
    {
        Socket client = newClient();
        client.setSoTimeout(60000);

        SocketChannel server = _connector.accept();
        server.configureBlocking(false);
        _manager.accept(server);

        __startBlocking.set(5);
        __blockFor.set(3);
        
        client.getOutputStream().write("Hello".getBytes(StandardCharsets.UTF_8));
        byte[] buffer = new byte[1024];
        int len=client.getInputStream().read(buffer);
        Assert.assertEquals(5, len);
        Assert.assertEquals("Hello",new String(buffer,0,len,StandardCharsets.UTF_8));

        _dispatches.set(0);
        client.getOutputStream().write("World".getBytes(StandardCharsets.UTF_8));
        len=5;
        while(len>0)
            len-=client.getInputStream().read(buffer);
        Assert.assertEquals(0, len);
        client.close();
    }

    @Test
    public void testManyLines() throws Exception
    {
        final Socket client = newClient();
        client.setSoTimeout(10000);

        SocketChannel server = _connector.accept();
        server.configureBlocking(false);
        _manager.accept(server);

        final int LINES=20;
        final CountDownLatch count=new CountDownLatch(LINES);


        new Thread()
        {
            @Override
            public void run()
            {
                try
                {
                    BufferedReader in = new BufferedReader(new InputStreamReader(client.getInputStream(),StandardCharsets.UTF_8));
                    while(count.getCount()>0)
                    {
                        String line=in.readLine();
                        if (line==null)
                            break;
                        // System.err.println(line);
                        count.countDown();
                    }
                }
                catch(IOException e)
                {
                    e.printStackTrace();
                }
            }
        }.start();

        for (int i=0;i<LINES;i++)
        {
            client.getOutputStream().write(("HelloWorld "+i+"\n").getBytes(StandardCharsets.UTF_8));
            // System.err.println("wrote");
            if (i%1000==0)
            {
                client.getOutputStream().flush();
                Thread.sleep(10);
            }
        }

        Assert.assertTrue(count.await(20,TimeUnit.SECONDS));
        client.close();

    }

    @Test
    public void testInvalidLargeTLSFrame() throws Exception
    {
        // Use an application input buffer larger than the SSLEngine application buffer,
        // so that the SSLEngine reports BUFFER_UNDERFLOW (rather than BUFFER_OVERFLOW)
        // for the oversized TLS record while the encrypted input buffer is full.
        _inputBufferSize=64*1024;

        try (Socket client = new Socket())
        {
            client.connect(_connector.socket().getLocalSocketAddress());

            SocketChannel server = _connector.accept();
            server.configureBlocking(false);
            _manager.accept(server);

            // Create raw TLS record with invalid large length (20,000 bytes).
            byte[] bytes = new byte[20005];
            Arrays.fill(bytes, (byte)1);

            bytes[0] = 22; // record type
            bytes[1] = 3;  // major version
            bytes[2] = 3;  // minor version
            bytes[3] = 78; // record length 2 bytes / 0x4E20 / decimal 20,000
            bytes[4] = 32; // record length
            bytes[5] = 1;  // message type
            bytes[6] = 0;  // message length 3 bytes / 0x004E17 / decimal 19,991
            bytes[7] = 78;
            bytes[8] = 23;

            _dispatches.set(0);
            client.getOutputStream().write(bytes);

            // Sleep to see if the server spins (would indicate a bug).
            Thread.sleep(1000);
            Assert.assertTrue("server spinning on oversized TLS record: " + _dispatches.get() + " dispatches", _dispatches.get() < 128);

            // The server must close the connection rather than wait for more encrypted bytes.
            client.setSoTimeout(5000);
            try
            {
                int read;
                do
                {
                    read = client.getInputStream().read();
                }
                while (read >= 0);
                Assert.assertEquals(-1, read);
            }
            catch (SocketException e)
            {
                // Connection reset by the server closing with unread bytes.
            }
        }
    }


}
