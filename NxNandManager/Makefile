CC=g++
CFLAGS=-std=c++11 -Wall -fexceptions -DUNICODE -D_UNICODE -DWIN32 -DMINGW_HAS_SECURE_API -Os
EXEC_NAME=NxNandManager.exe
INCLUDES=-I"C:\Users\elibo\OneDrive\Documents\Switch\openssl-1.1.1c-win64-mingw\include"
LIBINCLUDES=-L"C:\Users\elibo\OneDrive\Documents\Switch\openssl-1.1.1c-win64-mingw\lib"
INC=$(INCLUDES) $(LIBINCLUDES) 
LIBS=-L"C:\Users\elibo\OneDrive\Documents\Switch\openssl-1.1.1c-win64-mingw\lib" -lssl -lcrypto -lcrypt32 -lgdi32 -lws2_32
OBJ_FILES=utils.o hex_string.o xts_crypto.o NxStorage.o main.o
INSTALL_DIR=build

all : $(EXEC_NAME)

clean :
	rm -rf *.o

$(EXEC_NAME) : $(OBJ_FILES)
	$(CC) -o $(EXEC_NAME) $(OBJ_FILES) $(LIBS)

%.o: %.cpp
	$(CC) $(CFLAGS) $(INC) -o $@ -c $<

%.o: %.cc
	$(CC) $(CFLAGS) $(INC) -o $@ -c $<

%.o: %.c
	gcc $(CFLAGS) $(INC) -o $@ -c $<

install :
	cp $(EXEC_NAME) $(INSTALL_DIR)
