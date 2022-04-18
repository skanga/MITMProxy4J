package org.littleshoot.proxy;

import io.netty.handler.codec.http.HttpContent;
import io.netty.handler.codec.http.HttpHeaders;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpObject;
import io.netty.handler.codec.http.HttpRequest;
import io.netty.handler.codec.http.HttpResponse;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.commons.cli.UnrecognizedOptionException;
import org.apache.commons.lang3.StringUtils;
import org.apache.log4j.xml.DOMConfigurator;
import org.littleshoot.proxy.extras.SelfSignedMitmManager;
import org.littleshoot.proxy.impl.DefaultHttpProxyServer;
import org.littleshoot.proxy.impl.ProxyUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Map;

/*
c:\bin\curl -k --proxy http://localhost:8080 https://shortterm-2561.subnet1rg2phxsu.emdevinfraphx1.oraclevcn.com:7022/console/login/LoginForm.jsp
C:\bin\curl -k -i --proxy http://localhost:8080 "https://shortterm-2561.subnet1rg2phxsu.emdevinfraphx1.oraclevcn.com:7022/console/j_security_check" -X POST -H "Content-Type: application/x-www-form-urlencoded" --data-raw "j_username=weblogic&j_password=welcome1&j_character_encoding=UTF-8"
 */
public class LogProxy
{
    private static final Logger LOG = LoggerFactory.getLogger (LogProxy.class);
    private static final String OPTION_DNSSEC = "dnssec";
    private static final String OPTION_PORT = "port";
    private static final String OPTION_HELP = "help";
    private static final String OPTION_MITM = "mitm";
    private static final String OPTION_NIC = "nic";
    private static final String OPTION_LOG = "log";

    /**
     * Starts the proxy from the command line.
     *
     * @param args Any command line arguments.
     */
    public static void main (final String... args)
    {
        pollLog4JConfigurationFileIfAvailable ();
        LOG.info ("Running LittleProxy with args: {}", Arrays.asList (args));
        final Options options = new Options ();
        options.addOption (null, OPTION_DNSSEC, true, "Request and verify DNSSEC signatures.");
        options.addOption (null, OPTION_PORT, true, "Run on the specified port.");
        options.addOption (null, OPTION_NIC, true, "Run on a specified Nic");
        options.addOption (null, OPTION_LOG, true, "Log traffic to specified Log file");
        options.addOption (null, OPTION_HELP, false, "Display command line help.");
        options.addOption (null, OPTION_MITM, false, "Run as man in the middle.");

        final CommandLineParser parser = new DefaultParser ();
        final CommandLine cmd;
        try
        {
            cmd = parser.parse (options, args);
            if (cmd.getArgs ().length > 0)
            {
                throw new UnrecognizedOptionException ("Extra arguments were provided in " + Arrays.asList (args));
            }
        }
        catch (final ParseException e)
        {
            printHelp (options, "Could not parse command line: " + Arrays.asList (args));
            return;
        }
        if (cmd.hasOption (OPTION_HELP))
        {
            printHelp (options, null);
            return;
        }
        final int defaultPort = 8080;
        int port;
        if (cmd.hasOption (OPTION_PORT))
        {
            final String val = cmd.getOptionValue (OPTION_PORT);
            try
            {
                port = Integer.parseInt (val);
            }
            catch (final NumberFormatException e)
            {
                printHelp (options, "Unexpected port " + val);
                return;
            }
        }
        else
        {
            port = defaultPort;
        }
        final String defaultLogFile = "traffic.log";
        final String logFile;
        if (cmd.hasOption (OPTION_LOG))
            logFile = cmd.getOptionValue (OPTION_LOG);
        else
            logFile = defaultLogFile;

        HttpFiltersSource filtersSource = new HttpFiltersSourceAdapter ()
        {
            private final StringBuilder currCall = new StringBuilder ();

            @Override
            public HttpFilters filterRequest (HttpRequest originalRequest)
            {
                return new HttpFiltersAdapter (originalRequest)
                {
                    @Override
                    public HttpResponse proxyToServerRequest (HttpObject httpObject)
                    {
                        if (httpObject instanceof HttpRequest)  // REQUEST Headers recording
                        {
                            HttpRequest req = (HttpRequest) httpObject;
                            if (req.method ().compareTo (HttpMethod.CONNECT) == 0)
                                return null;

                            currCall.append (req.method ())
                                .append (" ")
                                .append (req.uri ())
                                .append (" ")
                                .append (req.protocolVersion ())
                                .append ("\n");
                            HttpHeaders headers = req.headers();
                            for (Map.Entry <String, String> header : headers.entries())
                            {
                                currCall.append (header.getKey ())
                                    .append (": ")
                                    .append (header.getValue ())
                                    .append ("\n");
                            }
                            currCall.append ("\n");
                        }
                        else if (httpObject instanceof HttpContent)  // REQUEST Body recording
                        {
                            currCall.append (((HttpContent) httpObject).content ().toString (StandardCharsets.UTF_8));
                            currCall.append ("\n");
                        }

                        return null;
                    }

                    @Override
                    public HttpObject serverToProxyResponse (HttpObject httpObject)
                    {
                        if (httpObject instanceof HttpResponse)  // RESPONSE Headers recording
                        {
                            HttpResponse resp = (HttpResponse) httpObject;

                            currCall.append ("\n")
                                .append (resp.protocolVersion ())
                                .append (" ")
                                .append (resp.status ().code ())
                                .append (" ")
                                .append (resp.status ().reasonPhrase ())
                                .append ("\n");
                            HttpHeaders headers = resp.headers();
                            for (Map.Entry <String, String> header : headers.entries())
                            {
                                currCall.append (header.getKey ())
                                    .append (": ")
                                    .append (header.getValue ())
                                    .append ("\n");
                            }
                            currCall.append ("\n");

                        }
                        else if (httpObject instanceof HttpContent)  // RESPONSE Body recording
                        {
                            currCall.append (((HttpContent) httpObject).content ().toString (StandardCharsets.UTF_8));
                            currCall.append ("\n");
                        }

                        // Write the req/resp to the log file
                        try
                        {
                            Files.write(Paths.get(logFile), currCall.toString().getBytes());
                        }
                        catch (IOException e)
                        {
                            System.out.println ("ERROR: Caught I/O Exception " + e.getMessage () + " while logging request");
                            System.out.println (currCall);
                        }

                        return httpObject;
                    }
                };
            }
        };

        System.out.println ("About to start server on port: " + port);
        HttpProxyServerBootstrap bootstrap = DefaultHttpProxyServer
            .bootstrapFromFile ("./littleproxy.properties")
            .withPort (port)
            .withManInTheMiddle (new SelfSignedMitmManager ())
            .withFiltersSource (filtersSource)
            .withAllowLocalOnly (false);

        if (cmd.hasOption (OPTION_NIC))
        {
            final String val = cmd.getOptionValue (OPTION_NIC);
            bootstrap.withNetworkInterface (new InetSocketAddress (val, 0));
        }

        if (cmd.hasOption (OPTION_MITM))
        {
            LOG.info ("Running as Man in the Middle");
            bootstrap.withManInTheMiddle (new SelfSignedMitmManager ());
        }

        if (cmd.hasOption (OPTION_DNSSEC))
        {
            final String val = cmd.getOptionValue (OPTION_DNSSEC);
            if (ProxyUtils.isTrue (val))
            {
                LOG.info ("Using DNSSEC");
                bootstrap.withUseDnsSec (true);
            }
            else if (ProxyUtils.isFalse (val))
            {
                LOG.info ("Not using DNSSEC");
                bootstrap.withUseDnsSec (false);
            }
            else
            {
                printHelp (options, "Unexpected value for " + OPTION_DNSSEC + "=:" + val);
                return;
            }
        }

        System.out.println ("About to start...");
        bootstrap.start ();
    }

    private static void printHelp (final Options options, final String errorMessage)
    {
        if (!StringUtils.isBlank (errorMessage))
        {
            LOG.error (errorMessage);
            System.err.println (errorMessage);
        }

        final HelpFormatter formatter = new HelpFormatter ();
        formatter.printHelp ("littleproxy", options);
    }

    private static void pollLog4JConfigurationFileIfAvailable ()
    {
        File log4jConfigurationFile = new File ("src/test/resources/log4j.xml");
        if (log4jConfigurationFile.exists ())
        {
            DOMConfigurator.configureAndWatch (log4jConfigurationFile.getAbsolutePath (), 15);
        }
    }
}
