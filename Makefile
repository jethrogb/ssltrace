SOURCES=ssltrace.cpp openssl.cpp nss.cpp gnutls.cpp
HEADERS=ssltrace.h nssimpl.h nsstypes.h gnutlstypes.h
OBJECTS=$(SOURCES:.cpp=.o)
OUTPUT=ssltrace.so

all: $(SOURCES) $(HEADERS) $(OUTPUT) Makefile
	
$(OUTPUT): $(OBJECTS)
	g++ -g -shared -Wall $(OBJECTS) -o $@ -ldl

.cpp.o:
	g++ -g -fPIC -std=gnu++11 -Wall -I/usr/include/nspr -c $< -o $@

clean:
	rm -f $(OBJECTS) $(OUTPUT)
