
import base64
from base64 import b64decode
import binascii
import string
from Crypto.Cipher import AES


def fixed_xor (arg1,arg2):
	
	result = int(arg1, 16) ^ int(arg2, 16)
	return '{:x}'.format(result) 
	


def single_xor_cipher(arg_3_1):

	value = binascii.unhexlify(arg_3_1)
	strings = (''.join (chr (ord(character) ^ key_value) for character in value) for key_value in range(256))
	return (max(strings, key=lambda y: y.count(' ')))


def detection_XOR(arg_4_1) :
	file_obj = open(arg_4_1,'r')

	array = []

	for line in file_obj :
		array.append(single_xor_cipher(line.strip()) )

	return (max(array, key=lambda y: y.count(' ')))


def Repeated_Key_Xor(arg_5_1,key_5) :
	
	count = 0 ;
	strings = ''

	for character in arg_5_1:
		strings = strings + (chr(ord (character) ^ ord (key_5[count]) ))
		count = count + 1
		count = count % 4

	return strings.encode('hex')



def hamming_distance(arg1,arg2):
	value1 = ''.join( (format(ord(x),'b')).zfill(8)  for x in arg1 )
	value2 = ''.join( (format(ord(x),'b')).zfill(8)  for x in arg2 )
	

	counter = 0 
	if (len(value1) > len(value2) ):
		length = len(value2)
	else :
		length = len(value1)


	for x in range(length) :
		 if (value1[x] != value2[x] ) :
		 	counter = counter +1 

	return counter




def Breaking_Repeated_Key_Xor(arg_6_1) :
	pass 




def AES_decoder(arg_7_1,key_7_1):
	file_obj = open(arg_7_1,'r')
	file_content = file_obj.read()
	
	##decoding 
	file_content = b64decode(file_content)

	decipher = AES.new(key_7_1, AES.MODE_ECB)
	
	#lambda s: s[:-ord(s[len(s) - 1:])]
	display = lambda s: s[:-5]
	return  display(decipher.decrypt(file_content))


def is_AES_helper_function(coded_line):
	block_size = 16 
	numb_block = len(coded_line)/16 

	for x in range(numb_block) :
		for y in range(x+1,numb_block) :
			if coded_line[x*block_size:(x+1)*block_size] == coded_line[y*block_size:(y+1)*block_size]:
				return True
				
	return False

def	AES_detection(arg_8_1) :
	file_obj = open(arg_8_1,'r')

	for line in file_obj :
		line = line.strip()
		coded_line = line.decode('hex') 

		if (is_AES_helper_function(coded_line)):
			print line

def main():

	# conversion from hex to base64
	# part_[1]
	hex_string = ('49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d')
	string = bytearray (hex_string.decode('hex'))
	new_value = base64.b64encode(string)

	
	# part_[2]
	arg_2_1 = '1c0111001f010100061a024b53535009181c'
	arg_2_2 =  '686974207468652062756c6c277320657965'
	
	fixed_xor(arg_2_1,arg_2_2)


	#part_[3]
	arg_3_1 ='1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
	
	single_xor_cipher(arg_3_1)

	#part_[4]
	#detection of single character XOR 
	#reading input from file
	
	detection_XOR('part4.txt')

	#part_[5]

	arg_5_1 = 'Julio, get the stretch\nRide to Harlem, Hollywood\nJackson, Mississippi'
	key_5 = 'FIRE'

	Repeated_Key_Xor(arg_5_1 ,key_5)

	#part_[6]

	#breaking repeating XOR 
	#reading from file 

	Breaking_Repeated_Key_Xor('part6.txt')


	arg_6_1 = 'this is a test'
	arg_6_2 = 'wokka wokka!!!'
	hamming_distance(arg_6_1,arg_6_2)


	#part_[7]
	#AES in ECB mode
	key_7_1 = 'YELLOW SUBMARINE'
	AES_decoder('part7.txt',key_7_1)



	#part_[8]
	#detection_of_AES_in_ECB_mode

	AES_detection('part8.txt')

main()	




