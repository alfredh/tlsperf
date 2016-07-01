
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_IO_H
#include <io.h>
#endif
#include <sys/time.h>
#include <time.h>
#include <re.h>
#include "tlsperf.h"


#define DEBUG_MODULE "util"
#define DEBUG_LEVEL 6
#include <re_dbg.h>


uint64_t tmr_microseconds(void)
{
	struct timeval now;
	uint64_t usec;

	if (0 != gettimeofday(&now, NULL)) {
		DEBUG_WARNING("jiffies: gettimeofday() failed (%m)\n", errno);
		return 0;
	}

	usec  = (uint64_t)now.tv_sec * (uint64_t)1000000;
	usec += now.tv_usec;

	return usec;
}
