CC=g++
CFLAGS=-std=c++11 -fexceptions -DUNICODE -D_UNICODE -DWIN32_LEAN_AND_MEAN
EXEC_NAME=NxNandManager.exe
INCLUDES=
LIBS=-static -lcrypto -lwsock32 -lws2_32
OBJ_FILES=res/utils.o res/hex_string.o res/fat32.o NxCrypto.o NxHandle.o NxPartition.o NxStorage.o main.o
INSTALL_DIR="/build"

all : $(EXEC_NAME)

clean :
	-@rm -rf *.o
	-@rm -rf res/*.o

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