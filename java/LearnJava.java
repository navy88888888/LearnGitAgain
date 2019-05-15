/**
 * default package
 */

import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Writer;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManagerFactory;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;

/**
 * A simple https server for running java code.
 * 
 * For more information please visit https://www.liaoxuefeng.com/
 * 
 * @author liaoxuefeng
 */
public class LearnJava {

	public static void main(String[] args) throws IOException, GeneralSecurityException, InterruptedException {
		KeyStore keystore = KeyStore.getInstance("JKS");
		keystore.load(new ByteArrayInputStream(Base64.getDecoder().decode(KEYSTORE_DATA)), KEYSTORE_PASSWD);
		KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
		kmf.init(keystore, KEYSTORE_PASSWD);
		// setup the trust manager factory
		TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
		tmf.init(keystore);
		// create https server
		HttpsServer server = HttpsServer.create(new InetSocketAddress(39193), 0);
		// create ssl context
		SSLContext sslContext = SSLContext.getInstance("SSL");
		// setup the HTTPS context and parameters
		sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
		server.setHttpsConfigurator(new HttpsConfigurator(sslContext) {
			public void configure(HttpsParameters params) {
				try {
					// initialise the SSL context
					SSLContext c = SSLContext.getDefault();
					SSLEngine engine = c.createSSLEngine();
					params.setNeedClientAuth(false);
					params.setCipherSuites(engine.getEnabledCipherSuites());
					params.setProtocols(engine.getEnabledProtocols());
					params.setSSLParameters(c.getDefaultSSLParameters());
				} catch (Exception ex) {
					ex.printStackTrace();
					System.out.println("Failed to create HTTPS server");
				}
			}
		});
		server.createContext("/", new CodeHandler());
		server.start();
		System.out.println("Ready for Java code on port 39193...\nPress Ctrl + C to exit...");
	}

	static ProcessResult runJavaProgram(String code) throws IOException, InterruptedException {
		String tmpDir = System.getProperty("java.io.tmpdir");
		File pwd = Paths.get(tmpDir, String.format("%016x", nextLong.incrementAndGet())).toFile();
		pwd.mkdirs();
		try (Writer writer = new BufferedWriter(new FileWriter(new File(pwd, "Main.java")))) {
			writer.write(code);
		}
		String[] command = new String[] { getJavaExecutePath(), "--source", "12", "--enable-preview", "-Dfile.encoding=UTF-8", "Main.java" };
		System.out.println(String.format("cd %s\n%s", pwd.toString(), String.join(" ", command)));
		ProcessBuilder pb = new ProcessBuilder().command(command).directory(pwd);
		pb.redirectErrorStream(true);
		Process p = pb.start();
		if (p.waitFor(5, TimeUnit.SECONDS)) {
			String result = null;
			try (InputStream input = p.getInputStream()) {
				result = readAsString(input);
			}
			return new ProcessResult(p.exitValue(), result);
		} else {
			System.err.println(String.format("Error: process %s timeout. destroy forcibly.", p.pid()));
			p.destroyForcibly();
			return new ProcessResult(p.exitValue(), "Timeout.");
		}
	}

	static class CodeHandler implements HttpHandler {
		@Override
		public void handle(HttpExchange exchange) throws IOException {
			String method = exchange.getRequestMethod();
			if ("GET".equals(method)) {
				sendResult(exchange, 0, "Server is ready.");
			} else {
				String body = readAsString(exchange.getRequestBody());
				if (!body.startsWith("code=")) {
					sendResult(exchange, 1, "No code found.");
				} else {
					String code = URLDecoder.decode(body.substring(5), StandardCharsets.UTF_8);
					System.out.println("========== prepare running code ==========");
					System.out.println(code);
					System.out.println("==========================================");
					try {
						ProcessResult result = runJavaProgram(code);
						System.out.println("================= result =================");
						System.out.println("exit code: " + result.exitCode);
						System.out.println(result.output);
						System.out.println("==========================================");
						sendResult(exchange, result.exitCode, result.output);
					} catch (InterruptedException e) {
						sendResult(exchange, 1, e.toString());
					}
				}
			}
		}

		void sendResult(HttpExchange exchange, int exitCode, String output) throws IOException {
			if (output.isEmpty()) {
				output = "(no output)";
			}
			sendData(exchange,
					String.format("{\"exitCode\":%s,\"output\":\"%s\"}", exitCode, encodeJsonString(output)));
		}

		void sendData(HttpExchange exchange, String s) throws IOException {
			String origin = exchange.getRequestHeaders().getOrDefault("Origin", List.of("https://www.liaoxuefeng.com"))
					.get(0);
			exchange.getResponseHeaders().set("Content-Type", "application/json");
			exchange.getResponseHeaders().set("Access-Control-Allow-Origin", origin);
			exchange.getResponseHeaders().set("Access-Control-Allow-Methods", "GET,POST");
			exchange.getResponseHeaders().set("Access-Control-Max-Age", "86400");
			exchange.sendResponseHeaders(200, 0);
			OutputStream os = exchange.getResponseBody();
			os.write(s.getBytes(StandardCharsets.UTF_8));
			os.close();
		}
	}

	static class ProcessResult {
		int exitCode;
		String output;

		public ProcessResult(int exitCode, String output) {
			this.exitCode = exitCode;
			this.output = output;
		}
	}

	static String readAsString(InputStream input) throws IOException {
		ByteArrayOutputStream output = new ByteArrayOutputStream();
		byte[] buffer = new byte[102400];
		for (;;) {
			int n = input.read(buffer);
			if (n == (-1)) {
				break;
			}
			output.write(buffer, 0, n);
		}
		return output.toString(StandardCharsets.UTF_8);
	}

	static String encodeJsonString(String s) {
		StringBuilder sb = new StringBuilder(s.length() + 1024);
		for (int i = 0; i < s.length(); i++) {
			char ch = s.charAt(i);
			switch (ch) {
			case '\"':
				sb.append("\\\"");
				break;
			case '\\':
				sb.append("\\\\");
				break;
			case '/':
				sb.append("\\/");
				break;
			case '\b':
				sb.append("\\b");
				break;
			case '\f':
				sb.append("\\f");
				break;
			case '\n':
				sb.append("\\n");
				break;
			case '\r':
				sb.append("\\r");
				break;
			case '\t':
				sb.append("    ");
				break;
			default:
				sb.append(ch);
				break;
			}
		}
		return sb.toString();
	}

	static String getJavaExecutePath() {
		if (javaExec == null) {
			String javaHome = System.getProperty("java.home");
			String os = System.getProperty("os.name");
			boolean isWindows = os.toLowerCase().startsWith("windows");
			Path javaPath = Paths.get(javaHome, "bin", isWindows ? "java.exe" : "java");
			javaExec = javaPath.toString();
		}
		return javaExec;
	}

	static String javaExec = null;

	static AtomicLong nextLong = new AtomicLong(System.currentTimeMillis());

	static char[] KEYSTORE_PASSWD = "8yg884f6s5n6ss8".toCharArray();

	static String KEYSTORE_DATA = "/u3+7QAAAAIAAAABAAAAAQAVbG9jYWwubGlhb3h1ZWZlbmcuY29tAAABZ3aPOQsA"
			+ "AAUCMIIE/jAOBgorBgEEASoCEQEBBQAEggTq52krWiOBUydzqPbr0BjbEYaBT8LLCyP2pBk3uzsjUFPePPej"
			+ "vbFbhjmHr/BbCO91iyk+mGeyeZNlnL565jM9JJVn+45Y5u4IdkVWqilXeqmHPdcwXin1/JorMcnpcXHA3GbE"
			+ "UdeT7C519Z2m2TeIImUU+wa3HylDV/ZCHqCIKFNzQRHdw80F5xkcIAu+NRv84pP44ZD17M+PnMrJwLtj4DP0"
			+ "4i+LdKhKKKFtTLJafMye/0qIIXNCs6iD+Gs+2MO+heu+KO4jWJHSmNIGVpZUeFKpp87Ze35jqC+xrAwg/y6M"
			+ "QX4j/u9yy6IH/XGo9/Ri0aucjss2uFwwc+/aiAzy9AFAVHS8GHb1R2w8PXDd7a7YriTNaR1UsXvC0m4AB2CW"
			+ "3p7U9pxRMEcnlFdbQdbTuO5aRScvztwQrtllwGTzGjNoxf494yq0URhqDx+UrbwU6dD4ap/c31ZT268aaeWA"
			+ "STWsBGUsAa400rosHHT6JZEGaVwc+NPD8UsCdHspHzxIMjpPbn9netKfcGPbCJDLzwIprWBnIeVlfS95tvU0"
			+ "kHkioqVCav4ZrDEkeMEVnp8lmFDLaFFcstz8AQSvsyQHUfGhB3KuCOWw3fSZm+2gxMfosxT2wvmGFWmVpwIG"
			+ "MP+DPfEtRiBqgRGwQW0avWTDSZF6O2KwHB0smGWVzcsp7/mP36Oz6wHq46NMOhJhPDzwfOLhqd4IqMgdlYuG"
			+ "AVbrm+a7nSS2hIFc74FZ3YFabegJcG/7v2ZHeAfP7GmSHIoru+o38zllA7TAsduM802gINA0x0e0fttULPh3"
			+ "xGYvVAtJnkfUv4sReNS/PtpL2DYggY9dOEBi+edpa/3N3FFTgIE/1YA2Q8pa0aqMF+KYHE7R35Wnzt0T6LWY"
			+ "czbFuRrnPmJT9TmWXzwFDmnQs9faDOZJNC0ZvoFkrRgCd/7zYvIIo6dfhBUiCvrl+I6Li9clYBZ5ULK0xsFN"
			+ "IiQp8csdee9TNu70EX4RitYgtW0msCwVBBG79gHwEgX5h3FCVSqwGoopItczxJYNin7ejfias/twOYmmnPUK"
			+ "iIa5ZTnvyMhECscpiMKiILaqZpjibTd9P7Nvh2SzJKDgkhlOYgP6Da8hmuQdMvuuqTyJ2eCdWHtEtwWWaQtF"
			+ "WDh2+AaecccaGMZYZVZ1NuqyPUulRu88zPDaQsqtUbHoRu/8tlfoLCFM7KqrxkmiDT/C/CoCT+ocX8Qw1If8"
			+ "8UXGg9/twAacNSzPGvTsZ94eytDcA7t5ut7SuH/4/7lzMaExfEu0MWyWNi9/J/Jv4Rli9aNlSOyUjsiyZWPl"
			+ "cI2cT/CSMaPQ0pu1R0kU6yDr13vmLgkQpLEUspc+5hcOcgzoNUKzkRIVZDIdFZ4FLPTHZrKnSpdvh8QNpyyk"
			+ "bf7WYxYLDdb7MSGOACh8NKpfZ5kK8NRKm4otXgLfSbi/zwmwQPZA/VTSqzvdnL0rdwkZerwfRTvTE4rBQElR"
			+ "aHsIQm71qc8O2CCOppkrOaeaCcqRqiYxUigV2YhgMUgFWyB50tKVAoi8TTaPPWqM/KZkZ4O1V0XQYpORRtSQ"
			+ "fBWK0l2SXLL5henDXH12r9z7Hf/R8ptFMRWex1vqEWwCpzSOcGvP4hp/g0oWuzin7+a3umlTbXia7bSPxn/B"
			+ "Z7PExo02j30NO//d5+4QfBT7gCgIZzg37gAAAAQABVguNTA5AAAFmzCCBZcwggR/oAMCAQICEA52OR9DQuGw"
			+ "CLyHZDtT23wwDQYJKoZIhvcNAQELBQAwcjELMAkGA1UEBhMCQ04xJTAjBgNVBAoTHFRydXN0QXNpYSBUZWNo"
			+ "bm9sb2dpZXMsIEluYy4xHTAbBgNVBAsTFERvbWFpbiBWYWxpZGF0ZWQgU1NMMR0wGwYDVQQDExRUcnVzdEFz"
			+ "aWEgVExTIFJTQSBDQTAeFw0xODA3MDgwMDAwMDBaFw0xOTA3MDgxMjAwMDBaMCAxHjAcBgNVBAMTFWxvY2Fs"
			+ "LmxpYW94dWVmZW5nLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKzbNJ5Dq7fAauZWrRIW"
			+ "lFPRgenB8E3Ls1mjT7SARJ0RCT8qdktmKnHgh9q+o43aDvllB+OI7XmOBtYM+apzhqzA7pu3ecmca9F5wDMy"
			+ "jTb5kOUfs4jrx0mHZPQVQacdFd8zlv2ve87CQgP9QfqsskH1ksui7W1k4KENy1mHUCeAIy+I3SnAZrBobPyv"
			+ "sTPBPcbLFehOEsJ+iKFFXywUM6oEc9dEk/XC8YTke5P9ECXBEngjLquzTCYHUegO+PwDsrNI8wroA3/EcSZ7"
			+ "NDPgifvdZK03Z9ZdE9lsuL0Y0LwMOl7XYNJihL26cZfC4YHEEMBJdxZI6jan1tBDNhG/JR0CAwEAAaOCAnkw"
			+ "ggJ1MB8GA1UdIwQYMBaAFH/TmfOgRw4xAFZWIo63zJ7dygGKMB0GA1UdDgQWBBQ9FGzLL6Y8GAJXdAPtDCt8"
			+ "APXMpzAgBgNVHREEGTAXghVsb2NhbC5saWFveHVlZmVuZy5jb20wDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQW"
			+ "MBQGCCsGAQUFBwMBBggrBgEFBQcDAjBMBgNVHSAERTBDMDcGCWCGSAGG/WwBAjAqMCgGCCsGAQUFBwIBFhxo"
			+ "dHRwczovL3d3dy5kaWdpY2VydC5jb20vQ1BTMAgGBmeBDAECATCBgQYIKwYBBQUHAQEEdTBzMCUGCCsGAQUF"
			+ "BzABhhlodHRwOi8vb2NzcDIuZGlnaWNlcnQuY29tMEoGCCsGAQUFBzAChj5odHRwOi8vY2FjZXJ0cy5kaWdp"
			+ "dGFsY2VydHZhbGlkYXRpb24uY29tL1RydXN0QXNpYVRMU1JTQUNBLmNydDAJBgNVHRMEAjAAMIIBAwYKKwYB"
			+ "BAHWeQIEAgSB9ASB8QDvAHUAu9nfvB+KcbWTlCOXqpJ7RzhXlQqrUugakJZkNo4e0YUAAAFkeEN8BgAABAMA"
			+ "RjBEAiAqWzi+6yjczGD/Gvh8I1RYUCkTgJ5UNyINpeUQic+MzAIgNS4M3+01H6bxMlP8qrBzQ387k67VQOeq"
			+ "TyWuMWvf0OoAdgCHdb/nWXz4jEOZX73zbv9WjUdWNv9KtWDBtOr/XqCDDwAAAWR4Q3vGAAAEAwBHMEUCIGLj"
			+ "07BPCcJ1TJjdEBXquLubcjuf5zKBrLZaLly8G72xAiEAvc1Ts36/u0plhBEtTTEXpfvp2YRRUNKZky44QkDw"
			+ "XdowDQYJKoZIhvcNAQELBQADggEBACJGy6tTrD2ZZAZlTbxVkOpQ/UjHNvrbmqjxxdqxAkHy/BKa1BfSmSz9"
			+ "cntnVL2aHW2wdSXIATzXM9zV+ck4twiIjXH/waj5OaO9uoUtlXcpN64ZDYnszSNN1B6IR5ENlODyuIjkmVIF"
			+ "wAY5asrquioKENNCTC2V7zp6TD4yt43omSuOk7zz+BZTn58seQtYCQVM2yBDBm/X9o8BpJUSsq0RCfQ6qvQv"
			+ "/Ku5hC9vqvAji61+kEG9uvPhUZuZdGKUcFRfnIqto7FDt1F93CX+UkY6t4L3J3EUTpUCT+mio/AFslOOEUrY"
			+ "ic6sz5BW1UBoa5mfXbYrqWS3jWUC5VgFWJQABVguNTA5AAAEsjCCBK4wggOWoAMCAQICEAWAJn8G8pVTNI4c"
			+ "GFpe7i4wDQYJKoZIhvcNAQELBQAwYTELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcG"
			+ "A1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEgMB4GA1UEAxMXRGlnaUNlcnQgR2xvYmFsIFJvb3QgQ0EwHhcNMTcx"
			+ "MjA4MTIyODI2WhcNMjcxMjA4MTIyODI2WjByMQswCQYDVQQGEwJDTjElMCMGA1UEChMcVHJ1c3RBc2lhIFRl"
			+ "Y2hub2xvZ2llcywgSW5jLjEdMBsGA1UECxMURG9tYWluIFZhbGlkYXRlZCBTU0wxHTAbBgNVBAMTFFRydXN0"
			+ "QXNpYSBUTFMgUlNBIENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoFmvV/qYfsAJvGIdRZNT"
			+ "Iym0OUMATjilWmUfznwofhen/d7u72RxnFFP5b1RoFEJ28yYUdVFdnqSWnvpu3MZ1yCnQ9P1UvW7QIMCbMxh"
			+ "b8KKl3mgqhaD+9cD5l441MC0+9Pqr1+IXcmHziXI3k8+UCrYPM0MMWivceCU/QqDpqFXVYRAQIg9w8EeXxYD"
			+ "hw8MBsXSVlQb5LZ6AM43Uy1w3W0lQuY2dLvKKvQYkw7+4wJbAeRfGmYL0mQzkHha8Gjk2ylkhCJxIZ3ISmUw"
			+ "9Xc+mgZZNcRhCOT2VgJ1QG2v6Hx995Lcpmkw7BOsUQ51ve6Q5IpgkWpOghG33t3V8OjleQIDAQABo4IBTzCC"
			+ "AUswHQYDVR0OBBYEFH/TmfOgRw4xAFZWIo63zJ7dygGKMB8GA1UdIwQYMBaAFAPeUDVW0Uy7ZvCj4hsbw5ey"
			+ "PdFVMA4GA1UdDwEB/wQEAwIBhjAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwEgYDVR0TAQH/BAgw"
			+ "BgEB/wIBADA0BggrBgEFBQcBAQQoMCYwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBC"
			+ "BgNVHR8EOzA5MDegNaAzhjFodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRHbG9iYWxSb290Q0Eu"
			+ "Y3JsMEwGA1UdIARFMEMwNwYJYIZIAYb9bAECMCowKAYIKwYBBQUHAgEWHGh0dHBzOi8vd3d3LmRpZ2ljZXJ0"
			+ "LmNvbS9DUFMwCAYGZ4EMAQIBMA0GCSqGSIb3DQEBCwUAA4IBAQCt3VTo+XZb+DMytott95Q2L8id7JRWNl9h"
			+ "yk2BrXvJ2yuouf37AyJjGIoQJKelWjWP3p/FmeanK0D1S7iayQ0l09ODZzHmTkA1KI/zRwJnXwgQf4dW2eTh"
			+ "iukn9YeWMf+cEeH901KD4BpZ1OxLjyEizXTEYg6157XCJgwIkb5IeRibh+GAlROlxJ7amjSIBpEcMSkoJ1Ny"
			+ "Hd4rhW1vRVEPUKrW9Rl/dQCe4uNed04pBoGAncGJAVEQ/IElXvDgHKOiH2TmLf0xMIotSL4tQqp7lJVqbBdS"
			+ "3UDSHX21t00ntAYUGu4n21SH7z1h2Drt65INWXjKOl0VPQeJ+VciWEZhAAVYLjUwOQAABGQwggRgMIIDSKAD"
			+ "AgECAhAPW8Ohdst4niAgx4k8gWe0MA0GCSqGSIb3DQEBCwUAMFoxCzAJBgNVBAYTAklFMRIwEAYDVQQKEwlC"
			+ "YWx0aW1vcmUxEzARBgNVBAsTCkN5YmVyVHJ1c3QxIjAgBgNVBAMTGUJhbHRpbW9yZSBDeWJlclRydXN0IFJv"
			+ "b3QwHhcNMTYxMjA3MTIxNzM0WhcNMjUwNTEwMTIwMDAwWjBhMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGln"
			+ "aUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwg"
			+ "Um9vdCBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOI74RFy3qik06NXqlCijwt3kMmipe4S"
			+ "zpZbAQkgzAGTp04wt1P3Q8RpAFed4o0i3YcGQACBCc7OG4O/3807cUbi1mbHBbN2JxaPe54elX3ut0ijCNrW"
			+ "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"
			+ "pWCW52n9Axn9gB4HLiC65x3LPgI=";
}