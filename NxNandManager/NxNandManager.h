
#pragma once
#ifndef __NxNandManager_h__
#define __NxNandManager_h__

//#define ENABLE_GUI  1 // Comment this line to compile for CLI version only
#if defined(ENABLE_GUI)
#include "gui/mainwindow.h"
#include <QApplication>
#include <QtCore>
#endif

#include <windows.h>
#include <winioctl.h>
#include <stdio.h>
#include <ctime>
#include <clocale>
#include <string>
#include <fstream>
#include <iostream>

#include <Wincrypt.h>
#include <sys/types.h>
#include "res/types.h"
#include "res/utils.h"
#include "NxStorage.h"

//extern bool DEBUG_MODE;
using namespace std;


#endif


