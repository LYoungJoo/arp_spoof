all: arppac

arppac:
	g++ arppac.cpp -lpcap -o arppac

clean:
	rm arppac


