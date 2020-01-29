CC       = gcc
CXX      = g++
CXXFLAGS=-std=c++11 -fexceptions -DUNICODE -D_UNICODE -DWIN32_LEAN_AND_MEAN -fPIC
CFLAGS= -fPIC -Wno-enum-conversion -O3
EXEC_NAME=NxNandManager.exe
INCLUDES=
LIBS=-static -lcrypto -lwsock32 -lws2_32

# Sources of external libraries
SRC_ZLIB  = $(wildcard lib/ZipLib/extlibs/zlib/*.c)
SRC_LZMA  = $(wildcard lib/ZipLib/extlibs/lzma/*.c)
SRC_BZIP2 = $(wildcard lib/ZipLib/extlibs/bzip2/*.c)

# ZipLib sources
SRC = \
		$(wildcard *.cpp)        \
		$(wildcard res/*.cpp)        \
		$(wildcard lib/ZipLib/*.cpp)        \
		$(wildcard lib/ZipLib/detail/*.cpp)

#OBJ_FILES=res/utils.o res/hex_string.o res/fat32.o res/mbr.o res/win_ioctl.o NxCrypto.o NxHandle.o NxPartition.o NxStorage.o main.o

OBJS = \
		$(SRC:.cpp=.o)	   \
		$(SRC_ZLIB:.c=.o)  \
		$(SRC_LZMA:.c=.o)  \
		$(SRC_BZIP2:.c=.o)

INSTALL_DIR="/build"

all : $(EXEC_NAME)

clean :
	-@rm -rf *.o
	-@rm -rf res/*.o
	-@rm -rf lib/ZipLib/*.o
	-@rm -rf lib/ZipLib/detail/*.o
	-@rm -rf lib/ZipLib/extlibs/zlib/*.o
	-@rm -rf lib/ZipLib/extlibs/lzma/*.o
	-@rm -rf lib/ZipLib/extlibs/bzip2/*.o

$(EXEC_NAME): $(OBJS)
	$(CXX) -o $@ $^ $(LIBS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

%.o: %.cc 
	$(CC) $(CFLAGS) $(INCLUDES) $(LIBS) -c $< -o $@

install :
	cp $(EXEC_NAME) $(INSTALL_DIR)