// 2014-01-14T19:27:29+09:00
#include <sys/time.h>
#include <time.h>
#include <stdio.h>
main()
{
 time_t timer;
 struct tm *tptr;
 time(&timer);
 tptr = localtime(&timer);
 printf("%4d-%02d-%02dT%02d:%02d:%02d%+02.2d:00 \n ", 
        (tptr->tm_year)+1900, tptr->tm_mon+1, tptr->tm_mday,
         tptr->tm_hour, tptr->tm_min, tptr->tm_sec, - timezone / 3600);
}
