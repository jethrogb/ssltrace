SOURCES=ssltrace.cpp openssl.cpp nss.cpp gnutls.cpp symbols.cpp
HEADERS=ssltrace.h nssimpl.h nsstypes.h gnutlstypes.h symbols.h
OBJECTS=$(SOURCES:.cpp=.o)
OUTPUT=ssltrace.so

all: $(SOURCES) $(HEADERS) $(OUTPUT) Makefile
	
$(OUTPUT): $(OBJECTS)
	g++ -g -shared -Wall $(OBJECTS) -o $@ -ldl -ldw

.cpp.o:
	g++ -g -fPIC -std=gnu++11 -Wall -D_GNU_SOURCE -I/usr/include/nspr -I/usr/include/elfutils -c $< -o $@

clean:
	rm -f $(OBJECTS) $(OUTPUT)
