/*
 * transactions.c
 *
 */

#include "comms.h"
#include "transactions.h"


char rawTx[4097];
uint16_t rawTx_charLength = 0;
uint8_t nonce_int8[8];
uint8_t nonce_size = 1;
char nonce[17];

//Replace "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" with your private key (as hex string, without 0x at the beginning)
const char *Rop_privK = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    
const uint32_t Rop_chainID = 3;    //Ropsten chain ID


int RNG_func(uint8_t *dest, unsigned size) {
	/*
	 * The RNG function should fill 'size' random bytes into 'dest'. It should return 1 if
	 * 'dest' was filled with random data, or 0 if the random data could not be generated.
	 */
	int status = 0;
	uint32_t randNum = 0;

	for (int i=0; i<size; i++) {
		status = !HAL_RNG_GenerateRandomNumber(&hrng, &randNum);
		*dest = randNum >> 24;
		dest++;
	}

	return status;
}

/**
  * @brief			Create a transaction.
  * @param-output	rawTx: pointer to a string that will be filled with the generated transaction.
  * @param-output	rawTx_charLength: pointer to rawTx length value.
  * @param-input	chainID: chain ID of target blockchain.
  * @param-input	privK_char: pointer to a string containing the private key.
  * @param-input	to: pointer to a string containing the destination address.
  * @param-input	value: pointer to a string containing ETH amount to send (in wei).
  * @param-input	gas_limit: pointer to a string containing gas limit value.
  * @param-input	gas_price: pointer to a string containing gas price value.
  * @param-input	nonce: pointer to a string containing nonce value.
  * @param-input	data: pointer to a string of arbitrary data that will be encoded in the transaction.
  * @retval			int: 2 if an error occurred, else 0.
  */
int createTx(char *rawTx,
			uint16_t *rawTx_charLength,
			uint32_t chainID,
			char *privK_char,
			char *to,
			char *value,
			char *gas_limit,
			char *gas_price,
			char *nonce_char,
			char *data) {
	uECC_Curve curve = uECC_secp256k1();
	uECC_RNG_Function rng_function = &RNG_func;
	uint8_t hash_size = 32;
	uint8_t payload_size = 128;
	uint8_t data_bytesLength = strlen(data) + 1;
	uint16_t Tx_size = 256 + data_bytesLength;
	uint16_t uTx_charLength = 0;
    uint8_t pubK_size = uECC_curve_public_key_size(curve); //64 bytes for secp256k1
    uint8_t privK_size = uECC_curve_private_key_size(curve); //32 bytes for secp256k1
//	uint8_t pubK[pubK_size];
	uint8_t privK[privK_size];
	uint8_t k_seed[Tx_size + privK_size];
	uint8_t k_uint8[hash_size];
	uint32_t k[hash_size / 4];
	uint8_t payload_hash[hash_size];
	uint8_t rawSignature[pubK_size]; //64 bytes for secp256k1
	uint8_t uTx[Tx_size];
	char uTx_char[Tx_size];
    char *r = 0;
    char r_char[65];
    char *s = 0;
    char s_char[65];
    uint32_t v = 0;
    uint32_t recID = 0;
	uint8_t sign = 0;


	/** Encode unsigned transaction */
	/* This is the payload to hash. Signing this hash will give the r,s,v
	 * parameters needed for encoding the final signed transaction.
	 */
	uTx_charLength = gen_transaction(uTx_char, Tx_size, nonce_char, gas_price, gas_limit, to, value, data, r, s, chainID);
	///////Fix bug in RLP encoding
	if(uTx_char[2]==48){
		if(uTx_char[3]==48){
			uTx_char[2]=56;
		}
	}

	/** Hash & Sign */
	payload_size = (uTx_charLength - 1) / 2;
	hex2byte_arr(uTx_char, (payload_size + 1)*2, uTx, payload_size); //Convert payload from char to uint8
	hex2byte_arr(privK_char, (privK_size + 1)*2, privK, privK_size); //Convert privK from char to uint8
	/*** To avoid ECDSA nonce reuse exploit - BEGIN
	 * "#Signing a second message using the same K value [...] is what opens ECDSA to attack"
	 * (from https://github.com/Marsh61/ECDSA-Nonce-Reuse-Exploit-Example/blob/master/Attack-Main.py , line 70)
	 * To avoid this exploit, k is not randomly generated. It is obtained instead as
	 *     k = keccak256(uTx || privK)
	 * reducing the chanches of using the same k when signing different messages.
	 * */
	for (int i=0; i<payload_size; i++) {
		k_seed[i] = uTx[i];
	}
	for (int i=0; i<privK_size; i++) {
		k_seed[payload_size + i] = privK[i];
	}
	keccak256(k_seed, payload_size + privK_size, k_uint8); //Compute k from seed
	for (int i=0; i<8; i++) {
		k[i] = k_uint8[i*4 + 3] + (k_uint8[i*4 + 2] << 8) + (k_uint8[i*4 + 1] << 16) + (k_uint8[i*4] << 24);
	}
	/*** Exploit avoidance - END */
	keccak256(uTx, payload_size, payload_hash); //Compute digest from payload

	uECC_set_rng(rng_function); //DON'T REMOVE! Needed for uECC_sign
	uint32_t k_final[hash_size / 4];
	sign = uECC_sign_deterministic_custom(&privK, &payload_hash, hash_size, k, &rawSignature, &v, k_final, curve); //Sign digest

	/** Compute recovery ID */
	recID = v + (chainID << 1) + 35; /* From https://ethereum.stackexchange.com/a/62769 */

	/** Generate final signed transaction */
	int8_to_char(&rawSignature, privK_size, r_char);
	int8_to_char(&rawSignature[privK_size], privK_size, s_char);

	*rawTx_charLength = gen_transaction(rawTx, Tx_size, nonce_char, gas_price, gas_limit, to, value, data, r_char, s_char, recID);
	///////Fix bug in RLP encoding
	if(rawTx[4]==48){
		if(rawTx[5]==48){
			rawTx[4]=56;
		}
	}


	if (sign == 1){

		return 0;
	}
	else {

		return 2;
	}
}

/**
  * @brief			Create a transaction, trasmitting several debug data via UART.
  * @param-output	rawTx: pointer to a string that will be filled with the generated transaction.
  * @param-output	rawTx_charLength: pointer to rawTx length value.
  * @param-input	chainID: chain ID of target blockchain.
  * @param-input	privK_char: pointer to a string containing the private key.
  * @param-input	to: pointer to a string containing the destination address.
  * @param-input	value: pointer to a string containing ETH amount to send (in wei).
  * @param-input	gas_limit: pointer to a string containing gas limit value.
  * @param-input	gas_price: pointer to a string containing gas price value.
  * @param-input	nonce: pointer to a string containing nonce value.
  * @param-input	data: pointer to a string of arbitrary data that will be encoded in the transaction.
  * @retval			int: 2 if an error occurred, else 0.
  */
int createTx_debug(char *rawTx,
			uint16_t *rawTx_charLength,
			uint32_t chainID,
			char *privK_char,
			char *to,
			char *value,
			char *gas_limit,
			char *gas_price,
			char *nonce_char,
			char *data) {
	uECC_Curve curve = uECC_secp256k1();
	uECC_RNG_Function rng_function = &RNG_func;
	uint8_t hash_size = 32;
	uint8_t payload_size = 128;
	uint8_t data_bytesLength = strlen(data) + 1;
	uint16_t Tx_size = 256 + data_bytesLength;
	uint16_t uTx_charLength = 0;
    uint8_t pubK_size = uECC_curve_public_key_size(curve); //64 bytes for secp256k1
    uint8_t privK_size = uECC_curve_private_key_size(curve); //32 bytes for secp256k1
	uint8_t pubK[pubK_size];
	uint8_t privK[privK_size];
	uint8_t k_seed[Tx_size + privK_size];
	uint8_t k_uint8[hash_size];
	uint32_t k[hash_size / 4];
	uint8_t payload_hash[hash_size];
	uint8_t rawSignature[pubK_size]; //64 bytes for secp256k1
	uint8_t uTx[Tx_size];
	char uTx_char[Tx_size];
    char *r = 0;
    char r_char[65];
    char *s = 0;
    char s_char[65];
    uint32_t v = 0;
    uint32_t recID = 0;
	uint8_t sign = 0;


	/** Compute public key -- FOR DEBUG*/
    uint8_t keygen = 0;
	keygen = uECC_compute_public_key(privK, pubK, curve);

	/** Encode unsigned transaction */
	/* This is the payload to hash. Signing this hash will give the r,s,v
	 * parameters needed for encoding the final signed transaction.
	 */
	uTx_charLength = gen_transaction(uTx_char, Tx_size, nonce_char, gas_price, gas_limit, to, value, data, r, s, chainID);
	///////Fix bug in RLP encoding
	if(uTx_char[2]==48){
		if(uTx_char[3]==48){
			uTx_char[2]=56;
		}
	}


	/** Transmit unsigned Tx -- FOR DEBUG*/
	HAL_UART_Transmit(&huart3, uTx_char, uTx_charLength, 5000);
	HAL_UART_Transmit(&huart3, CR_LF, sizeof(CR_LF), 10);   // Sending in normal mode

	/** Hash & Sign */
	payload_size = (uTx_charLength - 1) / 2;
	hex2byte_arr(uTx_char, (payload_size + 1)*2, uTx, payload_size); //Convert payload from char to uint8
	hex2byte_arr(privK_char, (privK_size + 1)*2, privK, privK_size); //Convert privK from char to uint8
	/*** To avoid ECDSA nonce reuse exploit - BEGIN
	 * "#Singing a second message using the same K value [...] is what opens ECDSA to attack"
	 * (from https://github.com/Marsh61/ECDSA-Nonce-Reuse-Exploit-Example/blob/master/Attack-Main.py , line 70)
	 * To avoid this exploit, k is not randomly generated. It is obtained instead as
	 *     k = keccak256(uTx || privK)
	 * reducing the chanches of using the same k when signing different messages.
	 * */
	for (int i=0; i<payload_size; i++) {
		k_seed[i] = uTx[i];
	}
	for (int i=0; i<privK_size; i++) {
		k_seed[payload_size + i] = privK[i];
	}
	keccak256(k_seed, payload_size + privK_size, k_uint8); //Compute k from seed
	for (int i=0; i<8; i++) {
		k[i] = k_uint8[i*4 + 3] + (k_uint8[i*4 + 2] << 8) + (k_uint8[i*4 + 1] << 16) + (k_uint8[i*4] << 24);
	}
	/*** Exploit avoidance - END */
	keccak256(uTx, payload_size, payload_hash); //Compute digest from payload
	/** Transmit digest -- FOR DEBUG*/
	char hash_char[hash_size*2 + 1];
	int8_to_char(payload_hash, hash_size, hash_char);
	HAL_UART_Transmit(&huart3, hash_char, hash_size*2 + 1, 5000);
	HAL_UART_Transmit(&huart3, CR_LF, sizeof(CR_LF), 10);   // Sending in normal mode

	uECC_set_rng(rng_function); //DON'T REMOVE! Needed for uECC_sign
	uint32_t k_final[hash_size / 4];
	sign = uECC_sign_deterministic_custom(&privK, &payload_hash, hash_size, k, &rawSignature, &v, k_final, curve); //Sign digest

	/** Transmit k_final -- FOR DEBUG*/
	uint8_t k_final_uint8[hash_size];
	for (int i=0; i<8; i++) {
		k_final_uint8[i*4] = k_final[i] >> 24;
		k_final_uint8[i*4 + 1] = k_final[i] >> 16;
		k_final_uint8[i*4 + 2] = k_final[i] >> 8;
		k_final_uint8[i*4 + 3] = k_final[i];
	}
	char k_final_char[hash_size*2 + 1];
	int8_to_char(k_final_uint8, hash_size, k_final_char);
	HAL_UART_Transmit(&huart3, k_final_char, hash_size*2 + 1, 5000);
	HAL_UART_Transmit(&huart3, CR_LF, sizeof(CR_LF), 10);   // Sending in normal mode

	/** Verify signature -- FOR DEBUG*/
	uint8_t verify = 0;
	if (uECC_valid_public_key(&pubK, curve) == 1) {
		verify = uECC_verify(&pubK, &payload_hash, hash_size, &rawSignature, curve);
	}

	/** Compute recovery ID */
	recID = v + (chainID << 1) + 35; /* From https://ethereum.stackexchange.com/a/62769 */

	/** Generate final signed transaction */
	int8_to_char(&rawSignature, privK_size, r_char);
	int8_to_char(&rawSignature[privK_size], privK_size, s_char);
	/** Transmit r,s -- FOR DEBUG*/
	HAL_UART_Transmit(&huart3, r_char, hash_size*2 + 1, 5000);
	HAL_UART_Transmit(&huart3, CR_LF, sizeof(CR_LF), 10);   // Sending in normal mode
	HAL_UART_Transmit(&huart3, s_char, hash_size*2 + 1, 5000);
	HAL_UART_Transmit(&huart3, CR_LF, sizeof(CR_LF), 10);   // Sending in normal mode

	*rawTx_charLength = gen_transaction(rawTx, Tx_size, nonce_char, gas_price, gas_limit, to, value, data, r_char, s_char, recID);
	///////Fix bug in RLP encoding
	if(rawTx[4]==48){
		if(rawTx[5]==48){
			rawTx[4]=56;
		}
	}


	if (sign == 1){

		return 0;
	}
	else {

		return 2;
	}
}

/**
  * @brief			Same as createTx, but with elapsed clock cycles measured for benchmark. Transmits
  * 				measurings via UART.
  * 				The function is divided into the following measuring intervals:
  * 				Initialization, uTxRLP, Keccak256, uECCsign, XCubeCryptosign(if enabled), rawTxRLP.
  *
  * @brief			Create a transaction.
  * @param-output	rawTx: pointer to a string that will be filled with the generated transaction.
  * @param-output	rawTx_charLength: pointer to rawTx length value.
  * @param-input	chainID: chain ID of target blockchain.
  * @param-input	privK_char: pointer to a string containing the private key.
  * @param-input	to: pointer to a string containing the destination address.
  * @param-input	value: pointer to a string containing ETH amount to send (in wei).
  * @param-input	gas_limit: pointer to a string containing gas limit value.
  * @param-input	gas_price: pointer to a string containing gas price value.
  * @param-input	nonce: pointer to a string containing nonce value.
  * @param-input	data: pointer to a string of arbitrary data that will be encoded in the transaction.
  * @retval			int: 2 if an error occurred, else 0.
  */
int createTx_benchmark(char *rawTx,
			uint16_t *rawTx_charLength,
			uint32_t chainID,
			char *privK_char,
			char *to,
			char *value,
			char *gas_limit,
			char *gas_price,
			char *nonce_char,
			char *data) {
	/*----- Benchmark Initialization BEGIN -----*/
	c0 = DWT->CYCCNT;
	uECC_Curve curve = uECC_secp256k1();
	uECC_RNG_Function rng_function = &RNG_func;
	uint8_t hash_size = 32;
	uint8_t payload_size = 128;
	uint8_t data_bytesLength = strlen(data) + 1;
	uint16_t Tx_size = 256 + data_bytesLength;
	uint16_t uTx_charLength = 0;
    uint8_t pubK_size = uECC_curve_public_key_size(curve); //64 bytes for secp256k1
    uint8_t privK_size = uECC_curve_private_key_size(curve); //32 bytes for secp256k1
//	uint8_t pubK[pubK_size];
	uint8_t privK[privK_size];
	uint8_t k_seed[Tx_size + privK_size];
	uint8_t k_uint8[hash_size];
	uint32_t k[hash_size / 4];
	uint8_t payload_hash[hash_size];
	uint8_t rawSignature[pubK_size]; //64 bytes for secp256k1
	uint8_t uTx[Tx_size];
	char uTx_char[Tx_size];
    char *r = 0;
    char r_char[65];
    char *s = 0;
    char s_char[65];
    uint32_t v = 0;
    uint32_t recID = 0;
	uint8_t sign = 0;
	c1 = DWT->CYCCNT;
	deltaC = c1 - c0;
	deltaC_TX[0] = deltaC >> 16;
	deltaC_TX[1] = deltaC;
	HAL_UART_Transmit(&huart3, deltaC_TX, sizeof(deltaC_TX), 10);
	/*----- Benchmark Initialization END -----*/


	/*----- Benchmark uTxRLP BEGIN -----*/
	c0 = DWT->CYCCNT;
	/** Encode unsigned transaction */
	/* This is the payload to hash. Signing this hash will give the r,s,v
	 * parameters needed for encoding the final signed transaction.
	 */
	uTx_charLength = gen_transaction(uTx_char, Tx_size, nonce_char, gas_price, gas_limit, to, value, data, r, s, chainID);
	///////Fix bug in RLP encoding
	if(uTx_char[2]==48){
		if(uTx_char[3]==48){
			uTx_char[2]=56;
		}
	}
	c1 = DWT->CYCCNT;
	deltaC = c1 - c0;
	deltaC_TX[0] = deltaC >> 16;
	deltaC_TX[1] = deltaC;
	HAL_UART_Transmit(&huart3, deltaC_TX, sizeof(deltaC_TX), 10);
	/*----- Benchmark uTxRLP END -----*/

	/*----- Benchmark Keccak256 BEGIN -----*/
	c0 = DWT->CYCCNT;
	/** Hash & Sign */
	payload_size = (uTx_charLength - 1) / 2;
	hex2byte_arr(uTx_char, (payload_size + 1)*2, uTx, payload_size); //Convert payload from char to uint8
	hex2byte_arr(privK_char, (privK_size + 1)*2, privK, privK_size); //Convert privK from char to uint8
	/*** To avoid ECDSA nonce reuse exploit - BEGIN
	 * "#Singing a second message using the same K value [...] is what opens ECDSA to attack"
	 * (from https://github.com/Marsh61/ECDSA-Nonce-Reuse-Exploit-Example/blob/master/Attack-Main.py , line 70)
	 * To avoid this exploit, k is not randomly generated. It is obtained instead as
	 *     k = keccak256(uTx || privK)
	 * reducing the chanches of using the same k when signing different messages.
	 * */
	for (int i=0; i<payload_size; i++) {
		k_seed[i] = uTx[i];
	}
	for (int i=0; i<privK_size; i++) {
		k_seed[payload_size + i] = privK[i];
	}
	keccak256(k_seed, payload_size + privK_size, k_uint8); //Compute k from seed
	for (int i=0; i<8; i++) {
		k[i] = k_uint8[i*4 + 3] + (k_uint8[i*4 + 2] << 8) + (k_uint8[i*4 + 1] << 16) + (k_uint8[i*4] << 24);
	}
	/*** Exploit avoidance - END */
	keccak256(uTx, payload_size, payload_hash); //Compute digest from payload
	c1 = DWT->CYCCNT;
	deltaC = c1 - c0;
	deltaC_TX[0] = deltaC >> 16;
	deltaC_TX[1] = deltaC;
	HAL_UART_Transmit(&huart3, deltaC_TX, sizeof(deltaC_TX), 10);
	/*----- Benchmark Keccak256 END -----*/

	/*----- Benchmark uECCsign BEGIN -----*/
	c0 = DWT->CYCCNT;
	uECC_set_rng(rng_function); //DON'T REMOVE! Needed for uECC_sign
	uint32_t k_final[hash_size / 4];
	sign = uECC_sign_deterministic_custom(&privK, &payload_hash, hash_size, k, &rawSignature, &v, k_final, curve); //Sign digest

	/** Compute recovery ID */
	recID = v + (chainID << 1) + 35; /* From https://ethereum.stackexchange.com/a/62769 */
	c1 = DWT->CYCCNT;
	deltaC = c1 - c0;
	deltaC_TX[0] = deltaC >> 16;
	deltaC_TX[1] = deltaC;
	HAL_UART_Transmit(&huart3, deltaC_TX, sizeof(deltaC_TX), 10);
	/*----- Benchmark uECCsign END -----*/

	/*----- Benchmark finalRLP BEGIN -----*/
	c0 = DWT->CYCCNT;
	/** Generate final signed transaction */
	int8_to_char(&rawSignature, privK_size, r_char);
	int8_to_char(&rawSignature[privK_size], privK_size, s_char);

	*rawTx_charLength = gen_transaction(rawTx, Tx_size, nonce_char, gas_price, gas_limit, to, value, data, r_char, s_char, recID);
	///////Fix bug in RLP encoding
	if(rawTx[4]==48){
		if(rawTx[5]==48){
			rawTx[4]=56;
		}
	}
	c1 = DWT->CYCCNT;
	deltaC = c1 - c0;
	deltaC_TX[0] = deltaC >> 16;
	deltaC_TX[1] = deltaC;
	HAL_UART_Transmit(&huart3, deltaC_TX, sizeof(deltaC_TX), 10);
	/*----- Benchmark finalRLP END -----*/


	if (sign == 1){

		return 0;
	}
	else {

		return 2;
	}
}

/**
 * A submitted transaction includes the following information:
 * 1.	recipient – the receiving address (if an externally-owned account, the transaction will transfer value. If a contract account, the transaction will execute the contract code)
 * 2.	signature – the identifier of the sender. This is generated when the sender's private key signs the transaction and confirms the sender has authorised this transaction
 * 3.	value – amount of ETH to transfer from sender to recipient (in WEI, a denomination of ETH)
 * 4.	data – optional field to include arbitrary data
 * 5.	gasLimit – the maximum amount of gas units that can be consumed by the transaction. Units of gas represent computational steps
 * 6.	gasPrice – the fee the sender pays per unit of gas
 * (from https://ethereum.org/en/developers/docs/transactions/)
 *
 */
int gen_transaction(char *rawTx, uint16_t rawTx_size, char *nonce, char *gas_price, char *gas_limit, char *to, char *value, char *data, char *r, char *s, uint32_t v){
	EthereumSignTx tx;
	EthereumSig signature;
	uint64_t raw_tx_bytes[rawTx_size / 8];

    tx.nonce.size = size_of_bytes(strlen(nonce));
    hex2byte_arr(nonce, strlen(nonce), tx.nonce.bytes, tx.nonce.size);

    tx.gas_price.size = size_of_bytes(strlen(gas_price));
    hex2byte_arr(gas_price, strlen(gas_price), tx.gas_price.bytes, tx.gas_price.size);

    tx.gas_limit.size = size_of_bytes(strlen(gas_limit));
    hex2byte_arr(gas_limit, strlen(gas_limit), tx.gas_limit.bytes, tx.gas_limit.size);

    tx.to.size = size_of_bytes(strlen(to));
    hex2byte_arr(to, strlen(to), tx.to.bytes, tx.to.size);

    tx.value.size = size_of_bytes(strlen(value));
    hex2byte_arr(value, strlen(value), tx.value.bytes, tx.value.size);

	tx.data_initial_chunk.size = size_of_bytes(strlen(data));
	hex2byte_arr(data, strlen(data), tx.data_initial_chunk.bytes,
				 tx.data_initial_chunk.size);

    signature.signature_v = v;

    signature.signature_r.size = size_of_bytes(strlen(r));
    hex2byte_arr(r, strlen(r), signature.signature_r.bytes, signature.signature_r.size);

    signature.signature_s.size = size_of_bytes(strlen(s));
    hex2byte_arr(s, strlen(s), signature.signature_s.bytes, signature.signature_s.size);

    int length = wallet_ethereum_assemble_tx(&tx, &signature, raw_tx_bytes);
    int8_to_char((uint8_t *) raw_tx_bytes, length, rawTx);

	return 2*length+1;
}

int wallet_ethereum_assemble_tx(EthereumSignTx *msg, EthereumSig *tx, uint64_t *rawTx) {
    EncodeEthereumSignTx new_msg;
    EncodeEthereumTxRequest new_tx;
    memset(&new_msg, 0, sizeof(new_msg));
    memset(&new_tx, 0, sizeof(new_tx));

    wallet_encode_element(msg->nonce.bytes, msg->nonce.size,
                          new_msg.nonce.bytes, &(new_msg.nonce.size), false);
    wallet_encode_element(msg->gas_price.bytes, msg->gas_price.size,
                          new_msg.gas_price.bytes, &(new_msg.gas_price.size), false);
    wallet_encode_element(msg->gas_limit.bytes, msg->gas_limit.size,
                          new_msg.gas_limit.bytes, &(new_msg.gas_limit.size), false);
    wallet_encode_element(msg->to.bytes, msg->to.size, new_msg.to.bytes,
                          &(new_msg.to.size), false);
    wallet_encode_element(msg->value.bytes, msg->value.size,
                          new_msg.value.bytes, &(new_msg.value.size), false);
    wallet_encode_element(msg->data_initial_chunk.bytes,
                          msg->data_initial_chunk.size, new_msg.data_initial_chunk.bytes,
                          &(new_msg.data_initial_chunk.size), false);

    wallet_encode_int(tx->signature_v, &(new_tx.signature_v));
    wallet_encode_element(tx->signature_r.bytes, tx->signature_r.size,
                          new_tx.signature_r.bytes, &(new_tx.signature_r.size), true);
    wallet_encode_element(tx->signature_s.bytes, tx->signature_s.size,
                          new_tx.signature_s.bytes, &(new_tx.signature_s.size), true);

    int length = wallet_encode_list(&new_msg, &new_tx, rawTx);
    return length;
}

void keccak256(const uint8_t *data, uint16_t length, uint8_t *result) {

    SHA3_CTX context;
    keccak_init(&context);
    keccak_update(&context, (const unsigned char*)data, (size_t)length);
    keccak_final(&context, (unsigned char*)result);

    // Clear out the contents of what we hashed (in case it was secret)
    memset((char*)&context, 0, sizeof(SHA3_CTX));
}

