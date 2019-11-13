all : 1m_block

1m_block: main.o

        g++ -g -o 1m_block main.o -lnetfilter_queue

main.o:
        g++ -g -c -o main.o main.cpp

clean:
        rm -f 1m_block
        rm -f *.o
