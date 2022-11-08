/*
 * comms.h
 *
 *  Created on: 21 apr 2022
 *      Author: Redeye
 */

#ifndef INC_COMMS_H_
#define INC_COMMS_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "stm32f4xx_hal.h"


extern UART_HandleTypeDef huart3;

extern uint8_t CR_LF[2];

extern int testDone;
extern int iterationCount;

/* Benchmark variables */
extern uint32_t c0;
extern uint32_t c1;
extern uint32_t deltaC;
extern uint16_t deltaC_TX[2];

extern uint8_t _binary_data_start;


int imported_values(uint8_t *dest, unsigned size);


#endif /* INC_COMMS_H_ */
