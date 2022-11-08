/*
 * transactions.h
 *
 *  Created on: 20 apr 2022
 *      Author: Redeye
 */

#ifndef INC_TRANSACTIONS_H_
#define INC_TRANSACTIONS_H_


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "uECC.h"
#include "uECC_vli.h"
#include "RLP.h"
#include "utils.h"
#include "keccak256.h"

#include "stm32f4xx_hal.h"


extern RNG_HandleTypeDef hrng;

extern char rawTx[4097];
extern uint16_t rawTx_charLength;
extern uint8_t nonce_int8[8];
extern uint8_t nonce_size;
extern char nonce[17];

extern const char *Rop_privK;

extern const uint32_t Rop_chainID;    //Ropsten chain ID



int RNG_func(uint8_t *dest, unsigned size);

int createTx(char *rawTx,
			uint16_t *rawTx_charLength,
			uint32_t chainID,
			char *privK_char,
			char *to,
			char *value,
			char *gas_limit,
			char *gas_price,
			char *nonce_char,
			char *data);

int createTx_benchmark(char *rawTx,
			uint16_t *rawTx_charLength,
			uint32_t chainID,
			char *privK_char,
			char *to,
			char *value,
			char *gas_limit,
			char *gas_price,
			char *nonce_char,
			char *data);

int gen_transaction(char *rawTx, uint16_t rawTx_size, char *nonce, char *gas_price, char *gas_limit, char *to, char *value, char *data, char *r, char *s, uint32_t v);

int wallet_ethereum_assemble_tx(EthereumSignTx *msg, EthereumSig *tx, uint64_t *rawTx);

void keccak256(const uint8_t *data, uint16_t length, uint8_t *result);


#endif /* INC_TRANSACTIONS_H_ */
