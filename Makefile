LIB_DIR = src/civerly/largesboxes/

.PHONY: all clean

all: lib-largesboxes.so

lib-largesboxes.so:
	g++ -fPIC -shared -std=c++11 -o ${LIB_DIR}lib-largesboxes.so  ${LIB_DIR}lib-largesboxes.cpp

clean:
	rm -f ${LIB_DIR}lib-largesboxes.so
