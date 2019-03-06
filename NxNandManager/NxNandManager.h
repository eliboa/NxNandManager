#pragma once
#ifndef __NxNandManager_h__
	#define __NxNandManager_h__

    #define ENABLE_GUI  1 // Comment this line to compile for CLI version only

	#if defined(ENABLE_GUI)
		#include "mainwindow.h"
		#include <QApplication>
        #include <QtCore>
	#endif

	#include <windows.h>
	#include <winioctl.h>
	#include <stdio.h>
	#include <string>
	#include <fstream>
	#include <iostream>
	#include <ctime>
	#include <Wincrypt.h>
	#include <sys/types.h>
	#include "types.h"
	#include "utils.h"
	#include "NxStorage.h"

    //extern bool DEBUG_MODE;
	using namespace std;

	BOOL BYPASS_MD5SUM = FALSE;
	BOOL DEBUG_MODE = FALSE;
	BOOL FORCE = FALSE;
	BOOL LIST = FALSE;

#endif


