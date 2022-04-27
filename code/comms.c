/*
 * comms.c
 *
 *  Created on: 20 apr 2022
 *      Author: Redeye
 */

#include "comms.h"

//uint8_t CR[] = "\r";
//uint8_t LF[] = "\n";
uint8_t CR_LF[] = "\r\n";

int testDone = 1;
int iterationCount = 0;

uint32_t c0 = 0;
uint32_t c1 = 0;
uint32_t deltaC = 0;
uint16_t deltaC_TX[2];

/* This is needed to handle data written in memory */
uint8_t _binary_data_start;



int imported_values(uint8_t *dest, unsigned size) {
	/*
	 * The RNG function should fill 'size' random bytes into 'dest'. It should return 1 if
	 * 'dest' was filled with random data, or 0 if the random data could not be generated.
	 */
	int status = 1;
	uint8_t *memPointer = &_binary_data_start + size*iterationCount;

	for (int i=0; i<size; i++){
		*dest = *memPointer;
		dest++;
		memPointer++;
	}

	return status;
}

