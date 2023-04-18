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