#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <trusty_ipc.h>
#include <uapi/err.h>

#include "cast_auth_impl.h"

int main() {
  CastAuthImpl impl;
  return impl.run_service();
}
