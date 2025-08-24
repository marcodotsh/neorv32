// ================================================================================ //
// The NEORV32 RISC-V Processor - https://github.com/stnolting/neorv32              //
// Copyright (c) NEORV32 contributors.                                              //
// Copyright (c) 2020 - 2025 Stephan Nolting. All rights reserved.                  //
// Licensed under the BSD-3-Clause license, see LICENSE for details.                //
// SPDX-License-Identifier: BSD-3-Clause                                            //
// ================================================================================ //


/**********************************************************************//**
 * @file demo_blink_led/main.c
 * @author Stephan Nolting
 * @brief Minimal blinking LED demo program using the lowest 8 bits of the GPIO.output port.
 **************************************************************************/
#include <neorv32.h>

// Define clock speed for delay calculation
#define CLOCK_FREQUENCY 27000000


/**********************************************************************//**
 * Simple busy-wait delay function.
 *
 * @param[in] time_ms Time in ms to wait (unsigned 32-bit).
 **************************************************************************/
void delay_ms(uint32_t time_ms) {

  // clock ticks per ms
  uint32_t ms_ticks = CLOCK_FREQUENCY / 1000;
  uint64_t wait_cycles = ((uint64_t)ms_ticks) * ((uint64_t)time_ms);
  // divide by clock cycles per iteration of the ASM loop (16)
  uint32_t iterations = (uint32_t)(wait_cycles >> 4);

  asm volatile (
    "0:                                             \n"
    "  beq  %[cnt_r], zero, 1f                      \n" // 3 cycles (if not taken)
    "  bne  zero, zero, 1f                          \n" // 3 cycles (never taken)
    "  addi %[cnt_w], %[cnt_r], -1                  \n" // 2 cycles
    "  nop                                          \n" // 2 cycles
    "  j    0b                                      \n" // 6 cycles
    "1:                                             \n"
    : [cnt_w] "=r" (iterations) : [cnt_r] "r" (iterations)
  );
}


/**********************************************************************//**
 * Main function; shows an incrementing 8-bit counter on GPIO.output(7:0).
 *
 * @note This program requires the GPIO controller to be synthesized.
 *
 * @return Will never return.
 **************************************************************************/
int main() {

  while (1) {
    neorv32_gpio_port_set(1);
    delay_ms(250);
    neorv32_gpio_port_set(2); 
    delay_ms(250);
  }

  // this should never be reached
  return 0;
}
