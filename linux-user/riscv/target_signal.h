#ifndef RISCV_TARGET_SIGNAL_H
#define RISCV_TARGET_SIGNAL_H

#include "../generic/signal.h"

#define TARGET_ARCH_HAS_SIGTRAMP_PAGE 1

#define TARGET_SEGV_PKUERR   4  /* Protection key violation */
#define TARGET_SEGV_CPERR   10  /* Control protection fault */

#endif /* RISCV_TARGET_SIGNAL_H */
