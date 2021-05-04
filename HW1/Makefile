CC=g++

all: hw1

hw1: hw1.cpp
	$(CC) $< -o $@

test: hw1
	./$<

clean:
	rm hw1

.PHONY: all test clean
