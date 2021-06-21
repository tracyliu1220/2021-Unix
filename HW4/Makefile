all: hw4

hw4: hw4.o commands.o commands.h
	g++ -o hw4 hw4.o commands.o commands.h -lcapstone

hw4.o: hw4.cpp commands.h
	g++ -c hw4.cpp

commands.o: commands.cpp commands.h
	g++ -c commands.cpp

.PHONY: all test clean

test: hw4
	./hw4

clean:
	rm -f *.o hw4
