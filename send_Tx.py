#External dependencies
from web3 import Web3
import serial


#HTTP provider (we use it to send transactions over Ropsten testnet)
web3 = Web3(Web3.HTTPProvider('https://eth-ropsten.alchemyapi.io/v2/xGKi1Hg-7gY-UBviXwL6ynbN0COZiZAN'))

#The following address must be associated to the board secret key 
from_address = '0xD9Ca30b79F3Df3D9b2cafCA316Eb2Ab759E77F14' 

#Receive nonce from network. In other words, obtain the count of transactions performed from the address from_address
nonce = web3.eth.getTransactionCount(from_address)

print("Address: "+from_address)
print("Current nonce value is "+str(nonce))


#Initialize serial port connection
serialPort = serial.Serial(port = 'COM3', baudrate=115200)

#The following instruction communicate with the board, by sending the nonce value
nonce_bytes = str(nonce).encode()
nonce_size = str(len(nonce_bytes)).encode();
serialString = serialPort.write(nonce_size)

serialString = serialPort.write(nonce_bytes)

serialString = "" # Used to hold data coming over UART

#The following loop receives 100 transactions from the board and submits them to the Ropsten test net
num_tx = 0
while(num_tx<100):

    #Wait until there is data waiting in the serial buffer
    if(serialPort.in_waiting > 0):
    
        #Read data out of the buffer until a carraige return / new line is found
        serialString = serialPort.readline()
         
        serialString_Ascii = serialString.decode('Ascii');
    
        #Read data from serial port (also, handle strings starting with '\x00')
        rawTx = "0x";

        i = 0;
        if len(serialString_Ascii)>0:
            if serialString_Ascii[i] == '\x00':
                i = 1;
            else:
                i = 0;
            while serialString_Ascii[i] != '\x00':
                rawTx = rawTx+serialString_Ascii[i];
                i = i+1;
            num_tx +=1 ;


            #Print rawTx
            nonce = nonce+1;
            print("Tx # "+str(nonce)+", RawTx = "+rawTx)
            
            tx_receipt = web3.eth.send_raw_transaction(rawTx);



            # Tell the device connected over the serial port that we recevied the data!
            ack_str = "0";
            serialString = serialPort.write(ack_str.encode())

            # The b at the beginning is used to indicate bytes!
            print("Transaction accepted, receipt is ")
            print(tx_receipt.hex())
            print("----------------------------------------------");