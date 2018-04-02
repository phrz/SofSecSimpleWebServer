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

public class SimpleWebServer {

	// Run the HTTP server on this TCP port. 
	private static final int PORT = 8080;

	// in bytes (5 MB)
	private static final int MAX_FILE_SIZE = 5_000_000;

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
		StringTokenizer tokenizer = new StringTokenizer(request, " ");

		String command = tokenizer.nextToken();
		String pathName = tokenizer.nextToken();

		if (command.equals("GET")) {
			// try to respond with the file
			// the user is requesting 
			serveFile(clientConnection, pathName);
		} else {
			// return an error saying this server
			// does not implement the requested command
			statusCode(clientConnection, 501);
		}

		// close the connection to the client 
		clientConnection.close();
	}

	public void statusCode(OutputStreamWriter clientConnection, int code) throws Exception {
		Map<Integer, String> codes = Map.of(
			200, "OK",
			403, "Forbidden",
			404, "Not Found",
			501, "Not Implemented"
		);
		String message = codes.get(code);
		clientConnection.write("HTTP/1.0 " + code + " " + message + "\n\n");
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
				logError("Attempted access to file larger than MAX_FILE_SIZE (" + pathName + ")");
				return;
			}
		}

		statusCode(clientConnection, 200); // OK
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
		
		SimpleWebServer sws = new SimpleWebServer();
		sws.run();
	}
}