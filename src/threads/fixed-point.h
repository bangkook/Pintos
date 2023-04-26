#include <stdint.h> 
#define Q 14
#define F 1<<Q
#define TO_REAL(n) (n)*(F)
#define TO_INT(x) (x) / (F)
#define TO_NEARINT(x) ((x) >= 0 ? ((x) + (F) / 2) / (F) : ((x) - (F) / 2) / (F))
#define ADD_REAL(x,y) (x)+(y)
#define SUB_REAL(x,y) (x)-(y)
#define ADD_REAL_INT(x,n) (x)+(n)*(F)
#define SUB_REAL_INT(x,n) (x)-(n)*(F)
#define MUL_REAL_INT(x,n) (x)*(n)
#define DIV_REAL_INT(x,n) (x)/(n)
#define MUL_REAL(x,y) ((int64_t)x)*(y)/(F)
#define DIV_REAL(x,y) ((int64_t)x)*(F)/(y)
/*
note:
int-> priority , nice , ready_threads

real->recent_cpu , load_avg


recent_cpu=ADD_REAL_INT(MUL_REAL(DIV_REAL((2*load_avg),ADD_REAL_INT((2*load_avg),1)),recent_cpu),nice);
priority=PRI_MAX-TO_NEARINT(recent_cpu/4)-(nice*2);
load_avg=MUL_REAL(DIV_REAL(TO_REAL(59),TO_REAL(60)),load_avg)+DIV_REAL(TO_REAL(1),TO_REAL(60))*ready_threads
*/