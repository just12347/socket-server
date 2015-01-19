all: install run

run:
	cat mycert.pem
	cat mykey.pem
	./server
install: 
	g++ -Wall ssl-server.cpp  -lpthread -o server -lssl -lcrypto
clean:
	rm server