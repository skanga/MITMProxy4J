package org.littleshoot.proxy.impl;

import com.google.common.net.HostAndPort;
import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFactory;
import io.netty.channel.ChannelHandler.Sharable;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelOption;
import io.netty.channel.ChannelPipeline;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.channel.udt.nio.NioUdtProvider;
import io.netty.handler.codec.http.HttpContent;
import io.netty.handler.codec.http.HttpMessage;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpObject;
import io.netty.handler.codec.http.HttpRequest;
import io.netty.handler.codec.http.HttpRequestEncoder;
import io.netty.handler.codec.http.HttpResponse;
import io.netty.handler.codec.http.HttpResponseDecoder;
import io.netty.handler.codec.http.LastHttpContent;
import io.netty.handler.timeout.IdleStateHandler;
import io.netty.handler.traffic.GlobalTrafficShapingHandler;
import io.netty.util.ReferenceCounted;
import io.netty.util.concurrent.Future;
import io.netty.util.concurrent.GenericFutureListener;
import org.littleshoot.proxy.ActivityTracker;
import org.littleshoot.proxy.ChainedProxy;
import org.littleshoot.proxy.ChainedProxyAdapter;
import org.littleshoot.proxy.ChainedProxyManager;
import org.littleshoot.proxy.FullFlowContext;
import org.littleshoot.proxy.HttpFilters;
import org.littleshoot.proxy.MitmManager;
import org.littleshoot.proxy.TransportProtocol;
import org.littleshoot.proxy.UnknownTransportProtocolException;
import org.slf4j.spi.LocationAwareLogger;

import javax.net.ssl.SSLSession;
import java.net.ConnectException;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.util.LinkedList;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;

import static org.littleshoot.proxy.impl.ConnectionState.AWAITING_CHUNK;
import static org.littleshoot.proxy.impl.ConnectionState.AWAITING_CONNECT_OK;
import static org.littleshoot.proxy.impl.ConnectionState.AWAITING_INITIAL;
import static org.littleshoot.proxy.impl.ConnectionState.CONNECTING;
import static org.littleshoot.proxy.impl.ConnectionState.DISCONNECTED;
import static org.littleshoot.proxy.impl.ConnectionState.HANDSHAKING;

/**
 * <p>
 * Represents a connection from our proxy to a server on the web.
 * ProxyConnections are reused fairly liberally, and can go from disconnected to
 * connected, back to disconnected and so on.
 * </p>
 *
 * <p>
 * Connecting a {@link ProxyToServerConnection} can involve more than just
 * connecting the underlying {@link Channel}. In particular, the connection may
 * use encryption (i.e. TLS) and it may also establish an HTTP CONNECT tunnel.
 * The various steps involved in fully establishing a connection are
 * encapsulated in the property {@link #connectionFlow}, which is initialized in
 * {@link #initializeConnectionFlow()}.
 * </p>
 */
@Sharable
public class ProxyToServerConnection extends ProxyConnection <HttpResponse>
{
    private final ClientToProxyConnection clientConnection;
    private final ProxyToServerConnection serverConnection = this;
    private volatile TransportProtocol transportProtocol;
    private volatile InetSocketAddress remoteAddress;
    private volatile InetSocketAddress localAddress;
    private final String serverHostAndPort;
    private volatile ChainedProxy chainedProxy;
    private final Queue <ChainedProxy> availableChainedProxies;

    /**
     * The filters to apply to response/chunks received from server.
     */
    private volatile HttpFilters currentFilters;

    /**
     * Encapsulates the flow for establishing a connection, which can vary
     * depending on how things are configured.
     */
    private volatile ConnectionFlow connectionFlow;

    /**
     * While we're in the process of connecting, it's possible that we'll
     * receive a new message to write. This lock helps us synchronize and wait
     * for the connection to be established before writing the next message.
     */
    private final Object connectLock = new Object ();

    /**
     * This is the initial request received prior to connecting. We keep track
     * of it so that we can process it after connection finishes.
     */
    private volatile HttpRequest initialRequest;

    /**
     * Keeps track of HttpRequests that have been issued so that we can
     * associate them with responses that we get back
     */
    private final Queue <HttpRequest> issuedRequests = new LinkedList <> ();

    /**
     * While we're doing a chunked transfer, this keeps track of the HttpRequest
     * to which we're responding.
     */
    private volatile HttpRequest currentHttpRequest;

    /**
     * While we're doing a chunked transfer, this keeps track of the initial
     * HttpResponse object for our transfer (which is useful for its headers).
     */
    private volatile HttpResponse currentHttpResponse;

    /**
     * Limits bandwidth when throttling is enabled.
     */
    private final GlobalTrafficShapingHandler trafficHandler;

    /**
     * Minimum size of the adaptive recv buffer when throttling is enabled.
     */
    private static final int MINIMUM_RECV_BUFFER_SIZE_BYTES = 64;

    /**
     * Create a new ProxyToServerConnection.
     */
    static ProxyToServerConnection create (DefaultHttpProxyServer proxyServer, ClientToProxyConnection clientConnection, String serverHostAndPort, HttpFilters initialFilters, HttpRequest initialHttpRequest, GlobalTrafficShapingHandler globalTrafficShapingHandler) throws UnknownHostException
    {
        Queue <ChainedProxy> chainedProxies = new ConcurrentLinkedQueue <> ();
        ChainedProxyManager chainedProxyManager = proxyServer.getChainProxyManager ();
        if (chainedProxyManager != null)
        {
            chainedProxyManager.lookupChainedProxies (initialHttpRequest, chainedProxies);
            if (chainedProxies.size () == 0)
            {
                // ChainedProxyManager returned no proxies, can't connect
                return null;
            }
        }
        return new ProxyToServerConnection (proxyServer, clientConnection, serverHostAndPort, chainedProxies.poll (), chainedProxies, initialFilters, globalTrafficShapingHandler);
    }

    private ProxyToServerConnection (DefaultHttpProxyServer proxyServer, ClientToProxyConnection clientConnection, String serverHostAndPort, ChainedProxy chainedProxy, Queue <ChainedProxy> availableChainedProxies, HttpFilters initialFilters, GlobalTrafficShapingHandler globalTrafficShapingHandler) throws UnknownHostException
    {
        super (DISCONNECTED, proxyServer, true);
        this.clientConnection = clientConnection;
        this.serverHostAndPort = serverHostAndPort;
        this.chainedProxy = chainedProxy;
        this.availableChainedProxies = availableChainedProxies;
        this.trafficHandler = globalTrafficShapingHandler;
        this.currentFilters = initialFilters;

        // Report connection status to HttpFilters
        currentFilters.proxyToServerConnectionQueued ();

        setupConnectionParameters ();
    }

    /***************************************************************************
     * Reading
     **************************************************************************/

    @Override
    protected void read (Object msg)
    {
        if (isConnecting ())
        {
            LOG.debug ("In the middle of connecting, forwarding message to connection flow: {}", msg);
            this.connectionFlow.read (msg);
        }
        else
        {
            super.read (msg);
        }
    }

    @Override
    protected ConnectionState readHTTPInitial (HttpResponse httpResponse)
    {
        LOG.debug ("Received raw response: {}", httpResponse);

        currentFilters.serverToProxyResponseReceiving ();

        rememberCurrentResponse (httpResponse);
        respondWith (httpResponse);

        if (ProxyUtils.isChunked (httpResponse))
        {
            return AWAITING_CHUNK;
        }
        else
        {
            currentFilters.serverToProxyResponseReceived ();

            return AWAITING_INITIAL;
        }
    }

    @Override
    protected void readHTTPChunk (HttpContent chunk)
    {
        respondWith (chunk);
    }

    @Override
    protected void readRaw (ByteBuf buf)
    {
        clientConnection.write (buf);
    }

    /**
     * <p>
     * Responses to HEAD requests aren't supposed to have content, but Netty
     * doesn't know that any given response is to a HEAD request, so it needs to
     * be told that there's no content so that it doesn't hang waiting for it.
     * </p>
     *
     * <p>
     * See the documentation for {@link HttpResponseDecoder} for information
     * about why HEAD requests need special handling.
     * </p>
     *
     * <p>
     * Thanks to <a href="https://github.com/nataliakoval">nataliakoval</a> for
     * pointing out that with connections being reused as they are, this needs
     * to be sensitive to the current request.
     * </p>
     */
    private class HeadAwareHttpResponseDecoder extends HttpResponseDecoder
    {

        public HeadAwareHttpResponseDecoder (int maxInitialLineLength, int maxHeaderSize, int maxChunkSize)
        {
            super (maxInitialLineLength, maxHeaderSize, maxChunkSize);
        }

        @Override
        protected boolean isContentAlwaysEmpty (HttpMessage httpMessage)
        {
            if (httpMessage instanceof HttpResponse)
            {
                // Identify our current request
                identifyCurrentRequest ();
            }

            return HttpMethod.HEAD.equals (currentHttpRequest.method ()) || super.isContentAlwaysEmpty (httpMessage);
        }
    }

    /***************************************************************************
     * Writing
     **************************************************************************/

    /**
     * Like {@link #write(Object)} and also sets the current filters to the
     * given value.
     */
    void write (Object msg, HttpFilters filters)
    {
        this.currentFilters = filters;
        write (msg);
    }

    @Override
    void write (Object msg)
    {
        LOG.debug ("Requested write of {}", msg);

        if (msg instanceof ReferenceCounted)
        {
            LOG.debug ("Retaining reference counted message");
            ((ReferenceCounted) msg).retain ();
        }

        if (is (DISCONNECTED) && msg instanceof HttpRequest)
        {
            LOG.debug ("Currently disconnected, connect and then write the message");
            connectAndWrite ((HttpRequest) msg);
        }
        else
        {
            if (isConnecting ())
            {
                synchronized (connectLock)
                {
                    if (isConnecting ())
                    {
                        LOG.debug ("Attempted to write while still in the process of connecting, waiting for connection.");
                        clientConnection.stopReading ();
                        try
                        {
                            connectLock.wait (30000);
                        }
                        catch (InterruptedException ie)
                        {
                            LOG.warn ("Interrupted while waiting for connect monitor");
                        }
                    }
                }
            }

            // only write this message if a connection was established and is not in the process of disconnecting or
            // already disconnected
            if (isConnecting () || getCurrentState ().isDisconnectingOrDisconnected ())
            {
                LOG.debug ("Connection failed or timed out while waiting to write message to server. Message will be discarded: {}", msg);
                return;
            }

            LOG.debug ("Using existing connection to: {}", remoteAddress);
            doWrite (msg);
        }
    }

    @Override
    protected void writeHttp (HttpObject httpObject)
    {
        if (chainedProxy != null)
        {
            chainedProxy.filterRequest (httpObject);
        }
        if (httpObject instanceof HttpRequest)
        {
            HttpRequest httpRequest = (HttpRequest) httpObject;
            // Remember that we issued this HttpRequest for later
            issuedRequests.add (httpRequest);
        }
        super.writeHttp (httpObject);
    }

    /***************************************************************************
     * Lifecycle
     **************************************************************************/

    @Override
    protected void become (ConnectionState newState)
    {
        // Report connection status to HttpFilters
        if (getCurrentState () == DISCONNECTED && newState == CONNECTING)
        {
            currentFilters.proxyToServerConnectionStarted ();
        }
        else if (getCurrentState () == CONNECTING)
        {
            if (newState == HANDSHAKING)
            {
                currentFilters.proxyToServerConnectionSSLHandshakeStarted ();
            }
            else if (newState == AWAITING_INITIAL)
            {
                currentFilters.proxyToServerConnectionSucceeded (ctx);
            }
            else if (newState == DISCONNECTED)
            {
                currentFilters.proxyToServerConnectionFailed ();
            }
        }
        else if (getCurrentState () == HANDSHAKING)
        {
            if (newState == AWAITING_INITIAL)
            {
                currentFilters.proxyToServerConnectionSucceeded (ctx);
            }
            else if (newState == DISCONNECTED)
            {
                currentFilters.proxyToServerConnectionFailed ();
            }
        }
        else if (getCurrentState () == AWAITING_CHUNK && newState != AWAITING_CHUNK)
        {
            currentFilters.serverToProxyResponseReceived ();
        }

        super.become (newState);
    }

    @Override
    protected void becameSaturated ()
    {
        super.becameSaturated ();
        this.clientConnection.serverBecameSaturated (this);
    }

    @Override
    protected void becameWritable ()
    {
        super.becameWritable ();
        this.clientConnection.serverBecameWriteable (this);
    }

    @Override
    protected void timedOut ()
    {
        super.timedOut ();
        clientConnection.timedOut ();
    }

    @Override
    protected void disconnected ()
    {
        super.disconnected ();
        if (this.chainedProxy != null)
        {
            // Let the ChainedProxy know that we disconnected
            try
            {
                this.chainedProxy.disconnected ();
            }
            catch (Exception e)
            {
                LOG.error ("Unable to record connectionFailed", e);
            }
        }
        clientConnection.serverDisconnected (this);
    }

    @Override
    protected void exceptionCaught (Throwable cause)
    {
        int logLevel = LocationAwareLogger.WARN_INT;
        try
        {
            if (cause != null)
            {
                String causeMessage = cause.getMessage ();
                if (cause instanceof ConnectException)
                {
                    logLevel = LocationAwareLogger.DEBUG_INT;
                }
                else if (causeMessage != null)
                {
                    if (causeMessage.contains ("Connection reset by peer"))
                    {
                        logLevel = LocationAwareLogger.DEBUG_INT;
                    }
                    else if (causeMessage.contains ("event executor terminated"))
                    {
                        logLevel = LocationAwareLogger.DEBUG_INT;
                    }
                }
            }

            LOG.log (logLevel, "Caught an exception on ProxyToServerConnection", cause);
        }
        finally
        {
            if (!is (DISCONNECTED))
            {
                LOG.log (logLevel, "Disconnecting open connection");
                disconnect ();
            }
        }
        // This can happen if we couldn't make the initial connection due
        // to something like an unresolved address, for example, or a timeout.
        // There will not have been be any requests written on an unopened
        // connection, so there should not be any further action to take here.
    }

    /***************************************************************************
     * State Management
     **************************************************************************/
    public TransportProtocol getTransportProtocol ()
    {
        return transportProtocol;
    }

    public InetSocketAddress getRemoteAddress ()
    {
        return remoteAddress;
    }

    public String getServerHostAndPort ()
    {
        return serverHostAndPort;
    }

    public boolean hasUpstreamChainedProxy ()
    {
        return getChainedProxyAddress () != null;
    }

    public InetSocketAddress getChainedProxyAddress ()
    {
        return chainedProxy == null ? null : chainedProxy.getChainedProxyAddress ();
    }

    public ChainedProxy getChainedProxy ()
    {
        return chainedProxy;
    }

    public HttpRequest getInitialRequest ()
    {
        return initialRequest;
    }

    @Override
    protected HttpFilters getHttpFiltersFromProxyServer (HttpRequest httpRequest)
    {
        return currentFilters;
    }

    /***************************************************************************
     * Private Implementation
     **************************************************************************/

    /**
     * An HTTP response is associated with a single request, so we can pop the
     * correct request off the queue.
     */
    private void identifyCurrentRequest ()
    {
        LOG.debug ("Remembering the current request.");
        // I'm a little unclear as to when the request queue would
        // ever actually be empty, but it is from time to time in practice.
        // We've seen this particularly when behind proxies that govern
        // access control on local networks, likely related to redirects.
        if (!this.issuedRequests.isEmpty ())
        {
            this.currentHttpRequest = this.issuedRequests.remove ();
            if (this.currentHttpRequest == null)
            {
                LOG.warn ("Got null HTTP request object.");
            }
        }
        else
        {
            LOG.debug ("Request queue is empty!");
        }
    }

    /**
     * Keeps track of the current HttpResponse so that we can associate its
     * headers with future related chunks for this same transfer.
     */
    private void rememberCurrentResponse (HttpResponse response)
    {
        LOG.debug ("Remembering the current response.");
        // We need to make a copy here because the response will be
        // modified in various ways before we need to do things like
        // analyze response headers for whether or not to close the
        // connection (which may not happen for a while for large, chunked
        // responses, for example).
        currentHttpResponse = ProxyUtils.copyMutableResponseFields (response);
    }

    /**
     * Respond to the client with the given {@link HttpObject}.
     */
    private void respondWith (HttpObject httpObject)
    {
        clientConnection.respond (this, currentFilters, currentHttpRequest, currentHttpResponse, httpObject);
    }

    /**
     * Connects to the server and then writes out the initial request (or
     * upgrades to an SSL tunnel, depending).
     */
    private void connectAndWrite (final HttpRequest initialRequest)
    {
        LOG.debug ("Starting new connection to: {}", remoteAddress);

        // Remember our initial request so that we can write it after connecting
        this.initialRequest = initialRequest;
        initializeConnectionFlow ();
        connectionFlow.start ();
    }

    /**
     * This method initializes our {@link ConnectionFlow} based on however this
     * connection has been configured.
     */
    private void initializeConnectionFlow ()
    {
        this.connectionFlow = new ConnectionFlow (clientConnection, this, connectLock).then (ConnectChannel);

        if (chainedProxy != null && chainedProxy.requiresEncryption ())
        {
            connectionFlow.then (serverConnection.EncryptChannel (chainedProxy.newSslEngine ()));
        }

        if (ProxyUtils.isCONNECT (initialRequest))
        {
            MitmManager mitmManager = proxyServer.getMitmManager ();
            boolean isMitmEnabled = mitmManager != null;

            if (isMitmEnabled)
            {
                connectionFlow.then (serverConnection.EncryptChannel (mitmManager.serverSslEngine (remoteAddress.getHostName (), remoteAddress.getPort ()))).then (clientConnection.RespondCONNECTSuccessful).then (serverConnection.MitmEncryptClientChannel);
            }
            else
            {
                // If we're chaining, forward the CONNECT request
                if (hasUpstreamChainedProxy ())
                {
                    connectionFlow.then (serverConnection.HTTPCONNECTWithChainedProxy);
                }

                connectionFlow.then (serverConnection.StartTunneling).then (clientConnection.RespondCONNECTSuccessful).then (clientConnection.StartTunneling);
            }
        }
    }

    /**
     * Opens the socket connection.
     */
    private final ConnectionFlowStep ConnectChannel = new ConnectionFlowStep (this, CONNECTING)
    {
        @Override
        boolean shouldExecuteOnEventLoop ()
        {
            return false;
        }

        @Override
        protected Future <?> execute ()
        {
            Bootstrap cb = new Bootstrap ().group (proxyServer.getProxyToServerWorkerFor (transportProtocol));

            switch (transportProtocol)
            {
                case TCP:
                    LOG.debug ("Connecting to server with TCP");
                    cb.channelFactory (new ChannelFactory <Channel> ()
                    {
                        @Override
                        public Channel newChannel ()
                        {
                            return new NioSocketChannel ();
                        }
                    });
                    break;
                case UDT:
                    LOG.debug ("Connecting to server with UDT");
                    cb.channelFactory (NioUdtProvider.BYTE_CONNECTOR).option (ChannelOption.SO_REUSEADDR, true);
                    break;
                default:
                    throw new UnknownTransportProtocolException (transportProtocol);
            }

            cb.handler (new ChannelInitializer <Channel> ()
            {
                protected void initChannel (Channel ch) throws Exception
                {
                    initChannelPipeline (ch.pipeline (), initialRequest);
                }
            });
            cb.option (ChannelOption.CONNECT_TIMEOUT_MILLIS, proxyServer.getConnectTimeout ());

            if (localAddress != null)
            {
                return cb.connect (remoteAddress, localAddress);
            }
            else
            {
                return cb.connect (remoteAddress);
            }
        }
    };

    /**
     * Writes the HTTP CONNECT to the server and waits for a 200 response.
     */
    private final ConnectionFlowStep HTTPCONNECTWithChainedProxy = new ConnectionFlowStep (this, AWAITING_CONNECT_OK)
    {
        protected Future <?> execute ()
        {
            LOG.debug ("Handling CONNECT request through Chained Proxy");
            chainedProxy.filterRequest (initialRequest);
            return writeToChannel (initialRequest);
        }

        void onSuccess (ConnectionFlow flow)
        {
            // Do nothing, since we want to wait for the CONNECT response to
            // come back
        }

        void read (ConnectionFlow flow, Object msg)
        {
            // Here we're handling the response from a chained proxy to our
            // earlier CONNECT request
            boolean connectOk = false;
            if (msg instanceof HttpResponse)
            {
                HttpResponse httpResponse = (HttpResponse) msg;
                int statusCode = httpResponse.status ().code ();
                if (statusCode >= 200 && statusCode <= 299)
                {
                    connectOk = true;
                }
            }
            if (connectOk)
            {
                flow.advance ();
            }
            else
            {
                flow.fail ();
            }
        }
    };

    /**
     * <p>
     * Encrypts the client channel based on our server {@link SSLSession}.
     * </p>
     *
     * <p>
     * This does not wait for the handshake to finish so that we can go on and
     * respond to the CONNECT request.
     * </p>
     */
    private final ConnectionFlowStep MitmEncryptClientChannel = new ConnectionFlowStep (this, HANDSHAKING)
    {
        @Override
        boolean shouldExecuteOnEventLoop ()
        {
            return false;
        }

        @Override
        boolean shouldSuppressInitialRequest ()
        {
            return true;
        }

        @Override
        protected Future <?> execute ()
        {
            return clientConnection.encrypt (proxyServer.getMitmManager ().clientSslEngineFor (sslEngine.getSession ()), false).addListener (new GenericFutureListener <Future <? super Channel>> ()
            {
                @Override
                public void operationComplete (Future <? super Channel> future) throws Exception
                {
                    if (future.isSuccess ())
                    {
                        clientConnection.setMitming (true);
                    }
                }
            });
        }
    };

    /**
     * <p>
     * Called to let us know that connection failed.
     * </p>
     *
     * <p>
     * Try connecting to a new address, using a new set of connection
     * parameters.
     * </p>
     *
     * @param cause the reason that our attempt to connect failed (can be null)
     * @return true if we are trying to fall back to another connection
     */
    protected boolean connectionFailed (Throwable cause) throws UnknownHostException
    {
        if (this.chainedProxy != null)
        {
            // Let the ChainedProxy know that we were unable to connect
            try
            {
                this.chainedProxy.connectionFailed (cause);
            }
            catch (Exception e)
            {
                LOG.error ("Unable to record connectionFailed", e);
            }
        }
        this.chainedProxy = this.availableChainedProxies.poll ();
        if (chainedProxy != null)
        {
            // Remove ourselves as handler on the old context
            this.ctx.pipeline ().remove (this);
            this.ctx.close ();
            this.ctx = null;
            this.setupConnectionParameters ();
            this.connectAndWrite (initialRequest);
            return true; // yes, we fell back
        }
        else
        {
            // nothing to fall back to.
            return false;
        }
    }

    /**
     * Set up our connection parameters based on server address and chained
     * proxies.
     */
    private void setupConnectionParameters () throws UnknownHostException
    {
        if (chainedProxy != null && chainedProxy != ChainedProxyAdapter.FALLBACK_TO_DIRECT_CONNECTION)
        {
            this.transportProtocol = chainedProxy.getTransportProtocol ();
            this.remoteAddress = chainedProxy.getChainedProxyAddress ();
            this.localAddress = chainedProxy.getLocalAddress ();
        }
        else
        {
            this.transportProtocol = TransportProtocol.TCP;

            // Report DNS resolution to HttpFilters
            this.remoteAddress = this.currentFilters.proxyToServerResolutionStarted (serverHostAndPort);

            // save the hostname and port of the unresolved address in hostAndPort, in case name resolution fails
            String hostAndPort = null;
            try
            {
                if (this.remoteAddress == null)
                {
                    hostAndPort = serverHostAndPort;
                    this.remoteAddress = addressFor (serverHostAndPort, proxyServer);
                }
                else if (this.remoteAddress.isUnresolved ())
                {
                    // filter returned an unresolved address, so resolve it using the proxy server's resolver
                    hostAndPort = HostAndPort.fromParts (this.remoteAddress.getHostName (), this.remoteAddress.getPort ()).toString ();
                    this.remoteAddress = proxyServer.getServerResolver ().resolve (this.remoteAddress.getHostName (), this.remoteAddress.getPort ());
                }
            }
            catch (UnknownHostException e)
            {
                // unable to resolve the hostname to an IP address. notify the filters of the failure before allowing the
                // exception to bubble up.
                this.currentFilters.proxyToServerResolutionFailed (hostAndPort);

                throw e;
            }

            this.currentFilters.proxyToServerResolutionSucceeded (serverHostAndPort, this.remoteAddress);

            this.localAddress = proxyServer.getLocalAddress ();
        }
    }

    /**
     * Initialize our {@link ChannelPipeline}.
     */
    private void initChannelPipeline (ChannelPipeline pipeline, HttpRequest httpRequest)
    {

        if (trafficHandler != null)
        {
            pipeline.addLast ("global-traffic-shaping", trafficHandler);
        }

        pipeline.addLast ("bytesReadMonitor", bytesReadMonitor);
        pipeline.addLast ("decoder", new HeadAwareHttpResponseDecoder (8192, 8192 * 2, 8192 * 2));
        pipeline.addLast ("responseReadMonitor", responseReadMonitor);

        // Enable aggregation for filtering if necessary
        int numberOfBytesToBuffer = proxyServer.getFiltersSource ().getMaximumResponseBufferSizeInBytes ();
        if (numberOfBytesToBuffer > 0)
        {
            aggregateContentForFiltering (pipeline, numberOfBytesToBuffer);
        }

        pipeline.addLast ("bytesWrittenMonitor", bytesWrittenMonitor);
        pipeline.addLast ("encoder", new HttpRequestEncoder ());
        pipeline.addLast ("requestWrittenMonitor", requestWrittenMonitor);

        // Set idle timeout
        pipeline.addLast ("idle", new IdleStateHandler (0, 0, proxyServer.getIdleConnectionTimeout ()));

        pipeline.addLast ("handler", this);
    }

    /**
     * <p>
     * Do all the stuff that needs to be done after our {@link ConnectionFlow}
     * has succeeded.
     * </p>
     *
     * @param shouldForwardInitialRequest whether or not we should forward the initial HttpRequest to
     *                                    the server after the connection has been established.
     */
    void connectionSucceeded (boolean shouldForwardInitialRequest)
    {
        become (AWAITING_INITIAL);
        if (this.chainedProxy != null)
        {
            // Notify the ChainedProxy that we successfully connected
            try
            {
                this.chainedProxy.connectionSucceeded ();
            }
            catch (Exception e)
            {
                LOG.error ("Unable to record connectionSucceeded", e);
            }
        }
        clientConnection.serverConnectionSucceeded (this, shouldForwardInitialRequest);

        if (shouldForwardInitialRequest)
        {
            LOG.debug ("Writing initial request: {}", initialRequest);
            write (initialRequest);
        }
        else
        {
            LOG.debug ("Dropping initial request: {}", initialRequest);
        }
    }

    /**
     * Build an {@link InetSocketAddress} for the given hostAndPort.
     *
     * @param hostAndPort String representation of the host and port
     * @param proxyServer the current {@link DefaultHttpProxyServer}
     * @return a resolved InetSocketAddress for the specified hostAndPort
     * @throws UnknownHostException if hostAndPort could not be resolved, or if the input string could not be parsed into
     *                              a host and port.
     */
    public static InetSocketAddress addressFor (String hostAndPort, DefaultHttpProxyServer proxyServer) throws UnknownHostException
    {
        HostAndPort parsedHostAndPort;
        try
        {
            parsedHostAndPort = HostAndPort.fromString (hostAndPort);
        }
        catch (IllegalArgumentException e)
        {
            // we couldn't understand the hostAndPort string, so there is no way we can resolve it.
            throw new UnknownHostException (hostAndPort);
        }

        String host = parsedHostAndPort.getHost ();
        int port = parsedHostAndPort.getPortOrDefault (80);

        return proxyServer.getServerResolver ().resolve (host, port);
    }

    /***************************************************************************
     * Activity Tracking/Statistics
     *
     * We track statistics on bytes, requests and responses by adding handlers
     * at the appropriate parts of the pipeline (see initChannelPipeline()).
     **************************************************************************/
    private final BytesReadMonitor bytesReadMonitor = new BytesReadMonitor ()
    {
        @Override
        protected void bytesRead (int numberOfBytes)
        {
            FullFlowContext flowContext = new FullFlowContext (clientConnection, ProxyToServerConnection.this);
            for (ActivityTracker tracker : proxyServer.getActivityTrackers ())
            {
                tracker.bytesReceivedFromServer (flowContext, numberOfBytes);
            }
        }
    };

    private final ResponseReadMonitor responseReadMonitor = new ResponseReadMonitor ()
    {
        @Override
        protected void responseRead (HttpResponse httpResponse)
        {
            FullFlowContext flowContext = new FullFlowContext (clientConnection, ProxyToServerConnection.this);
            for (ActivityTracker tracker : proxyServer.getActivityTrackers ())
            {
                tracker.responseReceivedFromServer (flowContext, httpResponse);
            }
        }
    };

    private final BytesWrittenMonitor bytesWrittenMonitor = new BytesWrittenMonitor ()
    {
        @Override
        protected void bytesWritten (int numberOfBytes)
        {
            FullFlowContext flowContext = new FullFlowContext (clientConnection, ProxyToServerConnection.this);
            for (ActivityTracker tracker : proxyServer.getActivityTrackers ())
            {
                tracker.bytesSentToServer (flowContext, numberOfBytes);
            }
        }
    };

    private final RequestWrittenMonitor requestWrittenMonitor = new RequestWrittenMonitor ()
    {
        @Override
        protected void requestWriting (HttpRequest httpRequest)
        {
            FullFlowContext flowContext = new FullFlowContext (clientConnection, ProxyToServerConnection.this);
            try
            {
                for (ActivityTracker tracker : proxyServer.getActivityTrackers ())
                {
                    tracker.requestSentToServer (flowContext, httpRequest);
                }
            }
            catch (Throwable t)
            {
                LOG.warn ("Error while invoking ActivityTracker on request", t);
            }

            currentFilters.proxyToServerRequestSending ();
        }

        @Override
        protected void requestWritten (HttpRequest httpRequest)
        {
        }

        @Override
        protected void contentWritten (HttpContent httpContent)
        {
            if (httpContent instanceof LastHttpContent)
            {
                currentFilters.proxyToServerRequestSent ();
            }
        }
    };
}
