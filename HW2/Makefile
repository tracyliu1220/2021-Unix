CC=gcc

all: logger.so logger

logger.so: logger_so.cpp
	$(CC) -o logger.so -shared -fPIC logger_so.cpp -ldl

logger: hw2.cpp
	g++ -o logger hw2.cpp

clean:
	rm -f logger logger.so

.PHONY: clean
