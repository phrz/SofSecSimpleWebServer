# SOFSEC SimpleWebServer Lab
## by Paul Herz

3. (Book question 7 a-c, pp. 78-79): 
Rewrite the serveFile() method such that it imposes a maximum file size limit. If a user attempts to download a file that is larger than the maximum allowed size, write a log entry to a file called error_log and return a “403 Forbidden” HTTP response code.

	a. What happens if an attacker tries to download /dev/random after you have made your modification?

		They get a "403 Forbidden": I designed my length checker to stop early if the file size read in thus far exceeded the MAX_FILE_SIZE constant I set (to 5MB). This prevents lockups. It would be smart, however, to disallow the server from serving "special files" (aka devices or file sockets).

	b. What might be some alternative ways in which to implement the maximum file size limit?

		I could check the size of the buffer less frequently to avoid the large overhead it probably imposes upon the reading process, like checking every kilobyte or so, and then invariably checking at the end of reading to make sure filesize is checked at least once. 

		I could also rely on platform-dependent filesystem metadata for file size information, as filesystems often store file size in their databases. I don't know how to do this in Java, but it is possible, and it avoids having to read the file up to the size limit in order to know whether the file is too big. 

		Checking if a file is special/device like /dev/random would obviate the need to continuously check file size, however, and then we could just check it at the end without worrying about infinite reading.

	c. [OPTIONAL] Implement multithreading and a mechanism that allows a maximum number of concurrent downloads for a particular IP address.

		(skipping)

4. (Book question 9 a-c, p. 79):
Implement basic HTTP authorization for SimpleWebServer. Read the HTTP 1.0 specification for more details on how basic HTTP authorization works.

	a. Instrument SimpleWebServer to store a username and password as data members. Require that any HTTP request to the web server be authorized by checking for an authorization HTTP header with a base64-encoded username and password. Requests that do not contain an authorization header should receive a WWW-Authentication challenge. Requests that do contain an authorization header should be authenticated against the username and password hard-coded in the SimpleWebServer class.

	b. Pretend that you are an attacker who got ahold of the compiled SimpleWebServer. class file. Run the strings utility on the compiled SimpleWebServer.class file to reveal the username and password that your modified web server requires. (If you are running a UNIX-based system, the strings utility is most likely preinstalled on your system. If you are running Windows, you can obtain the strings utility from www.sysinternals.com/Utilities/Strings.html).

	c. Install [WireShark] and a base64 decoder on your system. Make a few HTTP requests to your web server in which you use your username and pass- word to authenticate. Use [WireShark] to capture network traffic that is exchanged between your web client and server. Use the base64 decoder to convert the encoded username and password in the [WireShark] logs to plain text.