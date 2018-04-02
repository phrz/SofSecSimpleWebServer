default: run

run: build
	java SimpleWebServer

build:
	javac SimpleWebServer.java
