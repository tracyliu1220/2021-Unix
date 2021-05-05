CC=gcc
LARGE_FILE_FLAGS=-D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64

all: logger.so logger

logger.so: logger_so.cpp
	$(CC) -o logger.so -shared -fPIC logger_so.cpp -ldl

logger: hw2.cpp
	g++ -o logger hw2.cpp

testing: testing.cpp
	$(CC) -o testing testing.cpp

test: testing logger logger.so
	./logger ./testing

large: testing.cpp
	$(CC) -o large $(LARGE_FILE_FLAGS) testing.cpp

large_test: large logger logger.so
	./logger ./large

clean:
	rm -f logger logger.so testing large

.PHONY: clean test large_test
