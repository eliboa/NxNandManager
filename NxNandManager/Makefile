CC=g++
CFLAGS=-std=c++11 -Wall
EXEC_NAME=NxNandManager.exe
INCLUDES=
LIBS=
OBJ_FILES=utils.o NxStorage.o main.o
INSTALL_DIR=build

all : $(EXEC_NAME)

clean :
	rm -rf *.o

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
