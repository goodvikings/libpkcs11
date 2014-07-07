/*
 * ------------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <ramo -at- goodvikings -dot- com> wrote this file. As long as you retain this
 * notice you can do whatever you want with this stuff. If we meet some day, and
 * you think this stuff is worth it, you can buy me a beer in return - Ramo
 * ------------------------------------------------------------------------------
 */

#ifndef LOG_H
#define	LOG_H

#include <pthread.h>
#include <fstream>
#include "p11.h"

#define LOG_INSTANCE(filename) logger* log = logger::getInstance(filename)
#define LOG_DESTROY() logger::destroy()

#define LOG_EVENT(text) log->log_event(text, __FUNCTION__, __FILE__, __LINE__)
#define LOG_FUNCTIONCALL() log->log_functionCall(__FUNCTION__, __FILE__, __LINE__)
#define LOG_RETURNCODE(rc) log->log_returnCode(rc, __FUNCTION__, __FILE__, __LINE__)

class logger
{
public:
	static logger* getInstance(const char* filename);
	static void destroy();

	void log_event(const char* eventText, const char* func, const char* file, const long lineNo) const;
	void log_functionCall(const char* function, const char* file, const long lineNo) const;
	void log_returnCode(const CK_RV rc, const char* func, const char* file, const long lineNo) const;
private:
	static logger* instance;

	logger();
	~logger();
	const char* convertReturnVode(const CK_RV rv) const;

	std::ofstream* fout;
	pthread_mutex_t* lock;
};

#endif
