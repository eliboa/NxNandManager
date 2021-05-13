CC       = gcc
CXX      = g++
CXXFLAGS=-std=c++11 -fexceptions -DUNICODE -D_UNICODE -fPIC -fpermissive 
CFLAGS= -fPIC -Wno-enum-conversion -O3
EXEC_NAME=NxNandManager.exe
INCLUDES=-Ivirtual_fs/dokan/include 
LIBS=-static -lcrypto -lwsock32 -lws2_32 -Lvirtual_fs/dokan/x86/lib -ldokan1

# Sources of external libraries
SRC_ZLIB  = $(wildcard lib/ZipLib/extlibs/zlib/*.c)
SRC_LZMA  = $(wildcard lib/ZipLib/extlibs/lzma/*.c)
SRC_BZIP2 = $(wildcard lib/ZipLib/extlibs/bzip2/*.c)
SRC_FATFS = $(wildcard lib/fatfs/*.cpp)

# sources
SRC = \
	$(wildcard *.cpp)        \
	$(wildcard *.rc)        \
	$(wildcard res/*.cpp)        \
	$(wildcard virtual_fs/*.cpp)        \
	$(wildcard lib/ZipLib/*.cpp)        \
	$(wildcard lib/ZipLib/detail/*.cpp)

RCOBJ = $(patsubst %.rc,%.rc.o, $(wildcard gui/*.rc))
OBJS = $(RCOBJ) \
	$(SRC:.cpp=.o)     \
	$(SRC_ZLIB:.c=.o)  \
	$(SRC_LZMA:.c=.o)  \
	$(SRC_BZIP2:.c=.o) \
	$(SRC_FATFS:.cpp=.o)

INSTALL_DIR="/build"

all : $(EXEC_NAME)

clean :
	-@rm -rf *.o
	-@rm -rf gui/NxNandManager.tres
	-@rm -rf res/*.o
	-@rm -rf lib/ZipLib/*.o
	-@rm -rf lib/ZipLib/detail/*.o
	-@rm -rf lib/ZipLib/extlibs/zlib/*.o
	-@rm -rf lib/ZipLib/extlibs/lzma/*.o
	-@rm -rf lib/ZipLib/extlibs/bzip2/*.o
	-@rm -rf lib/fatfs/*.o

$(EXEC_NAME): $(OBJS)
	$(CXX) -o $@ $^ $(LIBS) 

$(RCOBJ) : %.rc.o : %.rc
	windres $^ -o $@

%.o: %.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

%.o: %.cc 
	$(CC) $(CFLAGS) $(INCLUDES) $(LIBS) -c $< -o $@

install :
	cp $(EXEC_NAME) $(INSTALL_DIR)