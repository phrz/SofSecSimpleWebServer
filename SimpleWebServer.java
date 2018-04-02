// SimpleWebServer.java
//
// This toy web server is used to illustrate security vulnerabilities.
// This web server only supports extremely simple HTTP GET requests.
//
// This file is also available at http://www.learnsecurity.com/ntk

import java.io.*;
import java.net.*;
import java.util.*;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Base64.*;

public class SimpleWebServer {

	// Run the HTTP server on this TCP port. 
	private static final int PORT = 8080;

	// in bytes (5 MB)
	private static final int MAX_FILE_SIZE = 5_000_000;

	// hardcoded credentials for Basic authentication
	// (as per instructions)
	private static final String USERNAME = "admin";
	private static final String PASSWORD = "letmein";

	// The socket used to process incoming connections
	// from web clients 
	private static ServerSocket serverSocket;

	public SimpleWebServer() throws Exception {
		System.out.println("Listening on :" + PORT);
		serverSocket = new ServerSocket(PORT);
	}

	public void run() throws Exception {
		while(true) {
			// wait for a connection from a client 
			Socket socket = serverSocket.accept();

			// then process the client's request 
			processRequest(socket);
		}
	}

	// Reads the HTTP request from the client, and
	// responds with the file the user requested or
	// a HTTP error code. 
	public void processRequest(Socket socket) throws Exception {
		// used to read data from the client 
		BufferedReader inputReader =
			new BufferedReader(
				new InputStreamReader(socket.getInputStream())
			);

		// used to write data to the client 
		OutputStreamWriter clientConnection = 
			new OutputStreamWriter(socket.getOutputStream());

		// read the HTTP request from the client 
		String request = inputReader.readLine();

		// parse the HTTP request 
		var requestTokenizer = new StringTokenizer(request, " ");

		String command = requestTokenizer.nextToken();
		String pathName = requestTokenizer.nextToken();

		// parse headers
		String line = null;
		var headers = new HashMap<String, String>();

		while((line = inputReader.readLine()) != null) {
			if(line.isEmpty()) {
				// blank line signifies end of headers (or no headers)
				break;
			}
			// "Header-Name: Header Field"
			int colonLocation = line.indexOf(':');
			if(colonLocation == -1) {
				logError(
					"Malformed header \""+line+"\" in request for \""+pathName+"\""+
					" (expected a colon delimiting header key and value."
				);
				statusCode(clientConnection, 400); // Bad Request
				endHeaders(clientConnection);
				return;
			}

			String headerName = line.substring(0, colonLocation);

			// header field may have leading whitespace
			// we simplify handling with String.trim() but a better implementation
			// would only strip it from the left.
			String headerField = line.substring(colonLocation + 1, line.length()).trim();

			headers.put(headerName, headerField);
		}

		// print request details to screen for debugging
		System.out.println(request);

		if(!command.equals("GET")) {
			statusCode(clientConnection, 501); // Not Implemented
			endHeaders(clientConnection);
		} else if(!checkBasicAuthentication(headers)) {
			// Basic authentication on all pages
			statusCode(clientConnection, 401); // Unauthorized
			// "The server generating a 401 response MUST send a 
			// WWW-Authenticate header field containing at least 
			// one challenge applicable to the target resource."
			writeHeader(clientConnection, "WWW-Authenticate", "Basic realm=\"DefaultRealm\"");
			endHeaders(clientConnection);
		} else {
			// command is GET, and is authorized.
			serveFile(clientConnection, pathName);
		}

		// close the connection to the client 
		clientConnection.close();
	}

	public Boolean checkBasicAuthentication(Map<String,String> headers) {
		String authorizationField = headers.get("Authorization");
		if(authorizationField == null) {
			return false;
		}

		String[] parts = authorizationField.split(" ");
		if(parts.length != 2) {
			// format must be exactly "Basic" + " " + <basic-cookie>
			return false;
		}

		if(!parts[0].equals("Basic")) {
			return false;
		}

		// try to decode the Base64 "basic-cookie" part
		byte[] authenticationCookieBytes = null;
		try {
			authenticationCookieBytes = Base64.getDecoder().decode(parts[1]);
		} catch(IllegalArgumentException e) {
			logError("Invalid base64 in Authorization: Basic header.");
			// we should return Bad Request here but because we're just printing
			// ad hoc to the client we can't do that. It would be better to use a mutable
			// object representing an HTTP Response (like most servers do), and then send
			// it in string form at the end, but I don't want to entirely rewrite this codebase.
			return false;
		}

		// decode(<authentication-cookie>) = username + ":" + password
		String authenticationCookie = new String(authenticationCookieBytes);
		int colonLocation = authenticationCookie.indexOf(":");

		if(colonLocation == -1) {
			logError("Invalid authentication cookie: expected colon.");
			// see above: it'd be nice to have an object-level response instance to mutate
			// before it's serialized, but we're just printing. Otherwise I'd send Bad Request.
			return false;
		}

		String givenUsername = authenticationCookie.substring(0, colonLocation);
		String givenPassword = authenticationCookie.substring(
			colonLocation + 1, 
			authenticationCookie.length()
		);

		// it'd be nice to use a constant-time comparison function here to avoid timing
		// attacks, but since we're using HTTP Basic Authentication unencrypted with hardcoded
		// credentials in the source code, we're far beyond the need for that.
		//
		// also, we'd normally look up a user record here, but there's exactly one hardcoded
		// user, so I simplify it to one line.
		return givenUsername.equals(USERNAME) && givenPassword.equals(PASSWORD);
	}

	public void statusCode(OutputStreamWriter clientConnection, int code) throws Exception {
		Map<Integer, String> codes = Map.of(
			200, "OK",
			401, "Unauthorized",
			403, "Forbidden",
			400, "Bad Request",
			404, "Not Found",
			501, "Not Implemented"
		);
		String message = codes.get(code);

		try {
			clientConnection.write("HTTP/1.0 " + code + " " + message + "\n");
		} catch(IOException e) {
			System.out.println("Could not write to client: " + e.getMessage());
		}
	}

	public void writeHeader(OutputStreamWriter clientConnection, String headerName, String headerField) {
		try {
			clientConnection.write(headerName + ": " + headerField + "\n");
		} catch(IOException e) {
			System.out.println("Could not write to client: " + e.getMessage());
		}
	}

	public void endHeaders(OutputStreamWriter clientConnection) {
		try {
			clientConnection.write("\n");
		} catch(IOException e) {
			System.out.println("Could not write to client: " + e.getMessage());
		}
	}

	public void serveFile(
		OutputStreamWriter clientConnection, 
		String pathName
	) throws Exception {
		FileReader fileReader = null;
		int endOfFile = -1;
		int character = endOfFile;
		StringBuffer buffer = new StringBuffer();

		// remove the initial slash at the beginning
		// of the pathname in the request 
		if(pathName.charAt(0) == '/') {
			pathName = pathName.substring(1);
		}

		// if there was no filename specified by the
		// client, serve the "index.html" file 
		if(pathName.equals("")) {
			pathName = "index.html";
		}

		// try to open file specified by pathname 
		try {
			fileReader = new FileReader(pathName);
			character = fileReader.read();
		} catch(Exception e) {
			statusCode(clientConnection, 404); // Not Found
			endHeaders(clientConnection);
			return;
		}

		// if the requested file can be successfully opened
		// and read, then return an OK response code and
		// send the contents of the file 
		

		while(character != endOfFile) {
			buffer.append((char) character);
			character = fileReader.read();

			if(buffer.length() > MAX_FILE_SIZE) {
				statusCode(clientConnection, 403); // Forbidden
				endHeaders(clientConnection);
				logError("Attempted access to file larger than MAX_FILE_SIZE (" + pathName + ")");
				return;
			}
		}

		statusCode(clientConnection, 200); // OK
		endHeaders(clientConnection);
		// response body
		clientConnection.write(buffer.toString());
	}

	public void logError(String message) {
		// ISO 8601 timestamp
		String timestamp = DateTimeFormatter
			.ofPattern("yyyy-MM-dd'T'HH:mmX")
			.withZone(ZoneOffset.UTC)
			.format(Instant.now());

		String logMessage = "[Error] " + timestamp + " - " + message;
		System.out.print(logMessage);

		try(Writer writer = new BufferedWriter(new FileWriter("error_log"))) {
			writer.write(logMessage + "\n");
		} catch(IOException e) {
			System.out.println("logError could not write to `error_log`: " + e.getMessage());
		}
	}

	public static void main(String argv[]) throws Exception {
		System.out.println("Starting web server...");
		
		SimpleWebServer server = new SimpleWebServer();
		server.run();
	}
}