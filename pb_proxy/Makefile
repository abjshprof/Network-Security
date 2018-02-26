pbproxy: args_parser.o  client.o  helpers.o  main.o  server.o
	gcc main.o server.o client.o args_parser.o helpers.o  -lm -lcrypto -lssl -o  pbproxy
clean:
	rm -f *.o
	rm -f pbproxy
	
