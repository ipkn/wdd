#pragma once

enum class SyscallCode : int
{
#define XX(a,b,c,d) a,
#include "syscall_defines.h"
#undef XX
};
