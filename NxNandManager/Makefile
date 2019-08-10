CC=g++
CFLAGS=-std=c++11 -Wall -fexceptions -DUNICODE -D_UNICODE -DWIN32_LEAN_AND_MEAN
EXEC_NAME=NxNandManager.exe
INCLUDES=
LIBS=-static -lcrypto -lwsock32 -lws2_32
OBJ_FILES=utils.o hex_string.o xts_crypto.o NxStorage.o main.o
INSTALL_DIR="/build"

all : $(EXEC_NAME)

clean :
	-@rm -rf *.o

$(EXEC_NAME) : $(OBJ_FILES)
	$(CC) -o $(EXEC_NAME) $(OBJ_FILES) $(LIBS)

%.o: %.cpp
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ -c $<

%.o: %.cc
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ -c $<

%.o: %.c
	gcc $(CFLAGS) $(INCLUDES) -o $@ -c $<

install :
	cp $(EXEC_NAME) $(INSTALL_DIR)