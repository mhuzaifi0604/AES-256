/*
Muhammad Huzaifa
20I-0604
Advanced Encryptaion Standard (AES Cipher) Implementation
CYSEC - T
Assignment # 03

*/

#include<iostream>
#include<iomanip>
#include<string>	//Inclusing
#include<string.h>	//Necessary
#include<cstring>	// Libraries
#include<sstream>
#include<algorithm>
#include<math.h>
#include "sbox.h"

using namespace std;

// Global sbox array
sbox_array s1;
inverse_sbox s2;
int rc = 0;		// Global variable for round constant adder

class Converters {
public:
	
	int char_to_int(char ch) { //function to convert character to integer
		int ascii = 0;
		if (ch >= 'a' && ch <= 'f') {
			ascii = int(ch) - 87;		//converting to integer in case of alphabbets
		}
		if (ch >= '0' && ch <= '9') {
			ascii = int(ch) - 48;		//converting to integers in case of Numerals
		}
		return ascii; // Returning integer value
	}

	string str_to_hex(string text) { // Function to conver atring to hexadecimal string
		string hex_result = "";
		stringstream ss;
		for (const auto& hexas : text) {
			ss << hex << int(hexas);
		}
		hex_result = ss.str();
		return hex_result;
	}

	int hex_to_int(string str) {	// Function to convert hexadec string to an integer
		unsigned int converted_hexa;
		istringstream iss(str);
		iss >> hex >> converted_hexa;
		return converted_hexa;
	}

	string GetHexFromBin(string sBinary){ // Function to convert hexa string to abinary one
		string rest = "", tmp, chr = "0000";
		int len = sBinary.length() / 4;
		for (int i = 0; i < sBinary.length(); i += 4){
			tmp = sBinary.substr(i, 4);
			if (!tmp.compare("0000"))
				rest = rest + "0";
			else if (!tmp.compare("0001"))
				rest = rest + "1";
			else if (!tmp.compare("0010"))
				rest = rest + "2";
			else if (!tmp.compare("0011"))
				rest = rest + "3";
			else if (!tmp.compare("0100"))
				rest = rest + "4";
			else if (!tmp.compare("0101"))
				rest = rest + "5";
			else if (!tmp.compare("0110"))
				rest = rest + "6";
			else if (!tmp.compare("0111"))
				rest = rest + "7";
			else if (!tmp.compare("1000"))
				rest = rest + "8";
			else if (!tmp.compare("1001"))
				rest = rest + "9";
			else if (!tmp.compare("1010"))
				rest = rest + "A";
			else if (!tmp.compare("1011"))
				rest = rest + "B";
			else if (!tmp.compare("1100"))
				rest = rest + "C";
			else if (!tmp.compare("1101"))
				rest = rest + "D";
			else if (!tmp.compare("1110"))
				rest = rest + "E";
			else if (!tmp.compare("1111"))
				rest = rest + "F";
			else
				continue;
		}
		return rest;
	}

	string int_to_hex(int val) { // Function to convert integer to a hexadec string
		ostringstream ss;
		ss << std::hex << val;
		string result = ss.str();
		return result;
	}

	string hex_to_bin(string hex) { // Function to convert hexa to a binary string
		int i = 0, check =0;
		string bin_val = "";
		while (hex[i]) {
			switch (hex[i]) {
			case '0':
				bin_val += "0000";break;
			case '1':
				bin_val += "0001";break;
			case '2':
				bin_val += "0010";break;
			case '3':
				bin_val += "0011";break;
			case '4':
				bin_val += "0100";break;
			case '5':
				bin_val += "0101";break;
			case '6':
				bin_val += "0110";break;
			case '7':
				bin_val += "0111";break;
			case '8':
				bin_val += "1000";break;
			case '9':
				bin_val += "1001";break;
			case 'a': case 'A':
				bin_val += "1010";break;
			case 'b': case 'B':
				bin_val += "1011";break;
			case 'c': case 'C':
				bin_val += "1100";break;
			case 'd': case 'D':
				bin_val += "1101";break;
			case 'e': case 'E':
				bin_val += "1110";break;
			case 'f': case 'F':
				bin_val += "1111";break;
			default:
				cout << "Invalid Hexa Entry" << endl;
				check = 1;
			}i++;
		}return bin_val;
	}

	string Xor_binaries(string bin1, string bin2) { //Function for xoring 2 binaries(strings)
		string xored = "";
		for (int i = 0; i < bin1.length(); i++) {
			if (bin1[i] == bin2[i])
				xored += "0";
			else
				xored += "1";
		}return xored;
	}

	string hex_to_str(string hexa) { // Function for converting hexa string to text 
		string converted = "";
		int base = 16;
		for (int i = 0; i < hexa.length(); i += 2) {
			string byte = hexa.substr(i, 2);
			char string_char = stoul(byte, nullptr, base);
			converted += string_char;
		}return converted;
	}
};

class gw_functions {
public:
	Converters c1;
	
	string rotator(string quad) {
		rotate(quad.begin(), quad.begin() + 2, quad.end());
		return quad;
	}
	
	int* sbox_subt(string gquad) {
		int *splitted = new int[4];
		int tempo, tempo2;
		string ss;
		int k = 0;
		for (int i = 0; i < 8; i += 2) {
			ss = gquad[i];
			tempo = c1.hex_to_int(ss);
			ss = gquad[i + 1];
			tempo2 = c1.hex_to_int(ss);
			splitted[k] = s1.sbox[tempo][tempo2];
			k++;	
		}
		return splitted;
	}
	
	string rc_adder(string str, int num, string* quads, int max) {
		string rcs[10] = {
			"00000001000000000000000000000000",
			"00000010000000000000000000000000",
			"00000100000000000000000000000000",
			"00001000000000000000000000000000",
			"00010000000000000000000000000000",
			"00100000000000000000000000000000",
			"01000000000000000000000000000000",
			"10000000000000000000000000000000",
			"00011011000000000000000000000000",
			"00110110000000000000000000000000"
		};
		char temp, temp1;
		string gwi = "", new_g = "";
		string to_xor = c1.hex_to_bin(quads[max - 8]);
		string binary_hex = c1.hex_to_bin(str);
		string binary_rc = rcs[num];
		int* int_bin_hex = new int[binary_hex.length()];
		int* int_bin_rc = new int[binary_hex.length()];
		int* gwi_binary = new int[binary_hex.length()];
		for (int i = 0; i < binary_hex.length(); i++) {
			int_bin_rc[i] = binary_rc[i] - 48;
			int_bin_hex[i] = binary_hex[i] - 48;
		}
		for (int i = 0; i < binary_hex.length(); i++) {
			gwi_binary[i] = int_bin_hex[i] ^ int_bin_rc[i];
			temp = (int_bin_hex[i] ^ int_bin_rc[i]) + 48;
			gwi += temp;
		}
		for (int i = 0; i < binary_hex.length(); i++) {
			gwi_binary[i] = gwi_binary[i] ^ (to_xor[i] - 48);
			temp = gwi_binary[i] + 48;
			new_g += temp;
		}
		rc += 1;
		return c1.GetHexFromBin(new_g);
	}
	
	void SBOX_printer() {
		cout << "\t\t printing the SBOX\n\n";
		cout << "\t\t";
		// Loop for Printing the SBOX
		for (int i = 0; i < 16; i++) {
			cout << "[	";
			for (int j = 0; j < 16; j++) {
				cout << "\033[95m" << s1.sbox[i][j] << "	" << "\033[0m";
			}
			cout << "]\n\t\t";
		}
	}
};

class base_functions { // Defining class that contains base functions requires for w_calculation
public:
	Converters c1;	// Declaring class objects
	gw_functions g1;
	
	string* quad_calc(string key) { // Function for 1st 08 w_s after initial key recieval
		string* w = new string[8];
		for (int i = 0; i < key.length(); i++) {	// Running a loop till length of key
			if (i >= 0 && i < 8)					// Storing Every
				w[0] += key[i];						//		|
			else if (i >= 8 && i < 16)				// 08 Hexa Characters
				w[1] += key[i];						//		|
			else if (i >= 16 && i < 24)				// Fro Recieved key
				w[2] += key[i];						//		|
			else if (i >= 24 && i < 32)				// In an array for ws
				w[3] += key[i];
			else if (i >= 32 && i < 40)
				w[4] += key[i];
			else if (i >= 40 && i < 48)
				w[5] += key[i];
			else if (i >= 48 && i < 56)
				w[6] += key[i];
			else if (i >= 56 && i < 64)
				w[7] += key[i];
		}return w;
	}

	string gw_calculator(string* quads, int max) { // Function for calculating the original gw
		string hex1;
		int* substituted = new int[4];
		string quad7 = g1.rotator(quads[max - 1]);	// Rotating the max index of W_s
		substituted = g1.sbox_subt(quad7);			// Substituting hexas from SBOX
		for (int i = 0; i < 4; i++) {
			if (substituted[i] < 16)				// Checking if substituted byte is a single character
				hex1 += "0";
			hex1 += c1.int_to_hex(substituted[i]);
		}return g1.rc_adder(hex1, rc, quads, max);	// Adding Round Constant
	}
	
	string mod_4_sub_w(string* quad, int max) { // Function for calculating w_s after every 4 w's
		string temp, left = quad[max - 8];
		char character;
		int* substituted = new int[4];
		substituted = g1.sbox_subt(quad[max - 1]); // Getting substituted SBOX chars for w[i-1]
		for (int i = 0; i < 4; i++) {
			if (substituted[i] < 16)
				temp += "0";						// Checking for single char values
			temp += c1.int_to_hex(substituted[i]);
		}
		string left_binary = c1.hex_to_bin(left),  temp_binary = c1.hex_to_bin(temp);
		int* left_bin = new int[left_binary.length()];
		int* temp_bin = new int[temp_binary.length()];
		for (int i = 0; i < left_binary.length(); i++) {
			left_bin[i] = left_binary[i] - 48;		// Converting string array to int
		}
		for (int i = 0; i < temp_binary.length(); i++) {
			temp_bin[i] = temp_binary[i] - 48;		// Converting string array to int
		}
		int* xored_bin = new int[left_binary.length()];
		string xored_val = "";
		for (int i = 0; i < left_binary.length(); i++) {
			xored_bin[i] = left_bin[i] ^ temp_bin[i];	// Xoring the int converted arrays
			character = xored_bin[i] + 48;				// Converting xored array back to string
			xored_val += character;
		}		
		return c1.GetHexFromBin(xored_val);				// Getting Hex value of string from xored binary
	}

	string simple_w_cal(string* quads, int max) {
		string left = quads[max - 8], right = quads[max - 1];
		string str_left_bin = c1.hex_to_bin(left), str_right_bin = c1.hex_to_bin(right);
		int* left_bin = new int[str_left_bin.length()], *right_bin = new int[str_right_bin.length()];
		for (int i = 0; i < str_left_bin.length(); i++) {
			left_bin[i] = str_left_bin[i] - 48;			// Converting string array to int
		}
		for (int i = 0; i < str_right_bin.length(); i++) {
			right_bin[i] = str_right_bin[i] - 48;		// Converting string array to int
		}
		char tempo;
		string final;
		int *xored = new int[str_left_bin.length()];
		for (int i = 0; i < str_left_bin.length(); i++) {
			xored[i] = left_bin[i] ^ right_bin[i];		// Xoring the int converted arrays
			tempo = xored[i] + 48;
			final += tempo;
		}
		return c1.GetHexFromBin(final);					// Getting Hex value of string from xored binary
	}
};

class round_prereqs {
public:


	string* key_generator(string* quads) { // Function for converting ws to requirred Keys
		string* keys = new string[15];
		int k = 0;
		for (int i = 0; i < 60; i += 4) {
			for (int j = i; j < i + 4; j++) {
				keys[k] += quads[j];		// Storing every 4 w's at each index of key array
			}k++;
		}return keys;
	}

	string** matrix_former(string key) {
		string* temp = new string[key.length() / 2]; // Getting a string of length 1/2 the n the key len
		string** matrix = new string * [4];
		for (int i = 0; i < 4; i++)
			matrix[i] = new string[4];				// Declaring a 2D array
		int k = 0;
		for (int i = 0; i < key.length(); i += 2) {
			for (int j = i; j < i + 2; j++) {
				temp[k] += key[j];					// Dividing key into stringds of size 2
			}k += 1;
		}k = 0;
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				matrix[j][i] = temp[k];				// Storing result in form of matrix
				k += 1;
			}
		}return matrix;
	}
};

class rounds {
public:
	Converters c1;

	string** round_0(string** pt, string** key) { // Function for key whitening process
		Converters c1;
		int temp;
		string** result = new string * [4];
		for (int i = 0; i < 4; i++)
			result[i] = new string[4]; // Declaring a 2D array
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				temp = c1.hex_to_int(pt[i][j]) ^ c1.hex_to_int(key[i][j]); // Xoring the plaintext and key for key whitening process
				if (temp < 16) {
					result[i][j] = "0" + c1.int_to_hex(temp); // Checking for a single char value
				}
				else
					result[i][j] = c1.int_to_hex(temp);		// Storing result into a matrix/ 2D array
			}
		}return result;
	}
	 
	string** shift_rows(string** state_matrix) { // Function for shifting rows 
		int iterator = 0, iterator2 = 0;
		string* temp = new string[4];
		string tempo = "";
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				temp[i] += state_matrix[i][j]; // storing row values in a atring
			}
			rotate(temp[i].begin(), temp[i].begin() + iterator, temp[i].end()); // left rotating the string
			tempo += temp[i];
			iterator += 2; // rotating next 2 chars on next iteration
			string tempo2;
			for (int k = 0; k < 4; k++, iterator2 += 2) {
				tempo2 = tempo[iterator2];
				tempo2 += tempo[iterator2 + 1];
				state_matrix[i][k] = tempo2; // stroring each byte at an index in matrix
			}
		}return state_matrix;
	}

	string** substitute_bytes(string** state_matrix) { //Function for substituting bytes from SBOX
		string temp = "";
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				temp = state_matrix[i][j];
				int tempo = c1.char_to_int(temp[0]);	// getting integer values of statematrix indeces
				int tempo2 = c1.char_to_int(temp[1]);
				int tempo3 = s1.sbox[tempo][tempo2];	//Getting value from SBOX to be substituted
				if (tempo3 < 16)
					state_matrix[i][j] = "0" + c1.int_to_hex(tempo3); // Check for single char value
				else
					state_matrix[i][j] = c1.int_to_hex(tempo3); // storing result in state matrix
			}
		}return state_matrix;
	}
	
	string** matrix_multiplication(string** state_matrix, string pre_defined[][4]) {
		string** mul = new string * [4];
		string temp = "";
		for (int i = 0; i < 4; i++)
			mul[i] = new string[4];		// Declaring a 2D array
		for (int i = 0; i < 4; ++i) {
			for (int j = 0; j < 4; ++j) {
				for (int k = 0; k < 4; k++) {
					string tempo1 = "", tempo2 = "";
					if (pre_defined[i][k] == "01") // Multiplication in case of 0x01
						tempo1 = state_matrix[k][j];
					else if (pre_defined[i][k] == "02") { // Multiplication in case of 0x02
						temp = c1.hex_to_bin(state_matrix[k][j]);
						for (int i = 1; i < temp.length(); i++)
							tempo2 += temp[i];
						tempo2 += "0"; // calculating the value with '0' LSB
						tempo1 = c1.GetHexFromBin(tempo2);
						if (temp[0] == '1') // Check for overflow
							tempo1 = c1.GetHexFromBin(c1.Xor_binaries(c1.hex_to_bin(tempo1), "00011011")); // XOring with '1B' in case of overflow 
					}
					else if (pre_defined[i][k] == "03") { // Multiplication in case of 0x03
						temp = c1.hex_to_bin(state_matrix[k][j]);
						for (int i = 1; i < temp.length(); i++)
							tempo2 += temp[i];
						tempo2 += "0"; // calculating the value with '0' LSB
						tempo1 = c1.GetHexFromBin(tempo2);
						tempo1 = c1.GetHexFromBin(c1.Xor_binaries(c1.hex_to_bin(tempo1), c1.hex_to_bin(state_matrix[k][j])));
						if (temp[0] == '1') // Check for overflow
							tempo1 = c1.GetHexFromBin(c1.Xor_binaries(c1.hex_to_bin(tempo1), "00011011"));// XOring with '1B' in case of overflow 
					}
					if (!mul[i][j].size())
						mul[i][j] = tempo1;
					else
						mul[i][j] = c1.GetHexFromBin(c1.Xor_binaries(c1.hex_to_bin(tempo1), c1.hex_to_bin(mul[i][j]))); // Xoring binaries& getting their hex value
				}
			}
		}return mul;
	}
};

class Decryption {
public:
	Converters c1;

	string** inverse_row_shifter(string** matrix) { // Function for shifting rows during decryption
		int iterator = 8, iterator2 = 0;
		string* temp = new string[4];
		string tempo = "";
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				temp[i] += matrix[i][j]; // Storing matrix row in a string
			}
			rotate(temp[i].begin(), temp[i].begin() + iterator, temp[i].end()); // right rotating the string 
			tempo += temp[i];
			iterator -= 2; // decrementing rotation for nex iteration/ row
			string tempo2;
			for (int k = 0; k < 4; k++, iterator2 += 2) {
				tempo2 = tempo[iterator2];
				tempo2 += tempo[iterator2 + 1];
				matrix[i][k] = tempo2; // storing rows again in matrix
			}
		}return matrix;
	}
	
	string** reverse_sbox_substitution( string** matrix) { // Function for SBOX substitution in decryption
			string temp = "";
			for (int i = 0; i < 4; i++) {
				for (int j = 0; j < 4; j++) {
					temp = matrix[i][j];
					int tempo = c1.char_to_int(temp[0]), tempo2 = c1.char_to_int(temp[1]);// getting int values of matrix indeces
					int tempo3 = s2.s_box_inverse[tempo][tempo2]; // Substituting from inverse sbox
					if (tempo3 < 16)
						matrix[i][j] = "0" + c1.int_to_hex(tempo3); // Checlk for single char value
					else
						matrix[i][j] = c1.int_to_hex(tempo3);
				}
			}return matrix;
		}

	string** inverse_matrix_multiplication(string** matrix) { // Function for matrix multi in decryption
		int** mul = new int * [4];
		int result = 0;
		for (int i = 0; i < 4; i++)
			mul[i] = new int[4];			// Creating a matrix/ 2D array
		for (int i = 0; i < 4; i++) { // Runnign loop for multiplication
			// Multiplication of matrices along with Xoring of each index
			mul[0][i] = nine[c1.hex_to_int(matrix[3][i])] ^ Bee[c1.hex_to_int(matrix[1][i])] ^ Dee[c1.hex_to_int(matrix[2][i])] ^ _0E[c1.hex_to_int(matrix[0][i])];
			mul[1][i] = nine[c1.hex_to_int(matrix[0][i])] ^ Bee[c1.hex_to_int(matrix[2][i])] ^ Dee[c1.hex_to_int(matrix[3][i])] ^ _0E[c1.hex_to_int(matrix[1][i])];
			mul[2][i] = nine[c1.hex_to_int(matrix[1][i])] ^ Bee[c1.hex_to_int(matrix[3][i])] ^ Dee[c1.hex_to_int(matrix[0][i])] ^ _0E[c1.hex_to_int(matrix[2][i])];
			mul[3][i] = nine[c1.hex_to_int(matrix[2][i])] ^ Bee[c1.hex_to_int(matrix[0][i])] ^ Dee[c1.hex_to_int(matrix[1][i])] ^ _0E[c1.hex_to_int(matrix[3][i])];
		}
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				matrix[i][j] = c1.int_to_hex(mul[i][j]); // Storing value in state matrix
				if (matrix[i][j].length() == 1)
					matrix[i][j] = "0" + matrix[i][j]; // Check for single char value
			}
		}return matrix;
	}

};

class Main_Menu {
public:
	Converters c1;
	round_prereqs p1;		//Declaring objects of diff classes
	rounds r1;
	Decryption d1;
	base_functions b1;
	
	string* w_s(string* quad_str) {
		
		string* all_ws = new string[60];
		for (int i = 0; i < 8; i++) {
			all_ws[i] = quad_str[i]; // storing 1st 08 w's already calculated
		}
		for (int i = 8; i < 60; i++) {
			if (i % 8 == 0)
				all_ws[i] = b1.gw_calculator(all_ws, i); // Calculating w[i+8]'s
			else if (i % 4 == 0)
				all_ws[i] = b1.mod_4_sub_w(all_ws, i); // Calculating w[i+4]'s
			else
				all_ws[i] = b1.simple_w_cal(all_ws, i); // Calculating simple w's from previous ones
		}
		cout << "\n\t\t Printing all W-Quads that are going to be used for Round-Keys" << endl;
		for (int i = 0; i < 60; i++)
			cout << "\n\t\t \033[94m" << "\t\t Quad" << i << " - w[" << i << "]: [ " << all_ws[i] << " ]" << "\033[0m" << endl;
		cout << endl;
		return all_ws;
	}

	string All_rounder(string plaintext, string* round_keys) {
		string encrypted = "";
		string pre_def[4][4] = { // Pre defined matrix for mat mult
		{"02", "03", "01", "01"}, {"01", "02", "03", "01"}, {"01", "01", "02", "03"}, {"03", "01", "01", "02"}
		};
		string** all_in_one = new string * [4];
		for (int i = 0; i < 4; i++)
			all_in_one[i] = new string[4]; // Declaring a 2D array
		cout << "\n\t\t Printing plaintext hexa: " << plaintext << endl;
		all_in_one = r1.round_0(p1.matrix_former(round_keys[0]), p1.matrix_former((plaintext))); // Calling round 0 for Key Whitening
		for (int i = 1; i < 14; i++) {
			all_in_one = r1.substitute_bytes(all_in_one);
			all_in_one = r1.shift_rows(all_in_one);					// Running every loop till q3th round
			all_in_one = r1.matrix_multiplication(all_in_one, pre_def);
			all_in_one = r1.round_0(all_in_one, p1.matrix_former(round_keys[i]));
		}
		all_in_one = r1.substitute_bytes(all_in_one);
		all_in_one = r1.shift_rows(all_in_one);			// 14th round excluding mix colomns
		all_in_one = r1.round_0(all_in_one, p1.matrix_former(round_keys[14]));
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++)
				encrypted += all_in_one[j][i]; // storing encrypted text in string
		}return encrypted;
	}

	string Decryptor(string* round_keys, string encryption, string** printer) {
		string decrypted;
		cout << "\n\t\t DECRYPTION " << endl;
		printer = r1.round_0(p1.matrix_former(round_keys[14]), p1.matrix_former(encryption)); // Key whitening in decryption
		for (int i = 13; i > 0; i--) {
			printer = d1.inverse_row_shifter(printer);		// Rounds 1 to 13
			printer = d1.reverse_sbox_substitution(printer);
			printer = r1.round_0(p1.matrix_former(round_keys[i]), printer);
			printer = d1.inverse_matrix_multiplication(printer);
		}
		printer = d1.inverse_row_shifter(printer);
		printer = d1.reverse_sbox_substitution(printer);	// round 14 excluding mix colomns
		printer = r1.round_0(p1.matrix_former(round_keys[0]), printer);
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++)
				decrypted += printer[j][i]; // storing decrypted text in string
		}return decrypted;
	}

	int Menu() {
		base_functions b1;
		gw_functions g1;
		string plaintext, in_key, encryption, decryption;
		int choice = 0;
		char choose;onceagain:
		string* quad_str = new string[8], * all_ws = new string[60], * round_keys = new string[15];
		string** printer = new string * [4];
		for (int i = 0; i < 4; i++)
			printer[i] = new string[4];
		cout << "\t\t\t :::::: - Advanced Encryption Standard (AES Cipher) - ::::::\n" << endl; // Dis[laying menu
		cout << "\t\t\t\t\t ::::::Reqired Inputs ::::::\n\n\t\t\t\t -> Plaintext to be Encrypted ~(128 bits)\n\t\t\t\t -> Key to Encrypt plaintext ~(256 bits)\n" << endl;
		cout << "\n\t\t --------------------------------------------------------------------------\n" << endl;
		again1:cout << "\t\t\t Enter the" << "\033[92m"<<" Plaintext " <<"\033[0m" << "to be Encrypted : "; // Taking plaintext input
		getline(cin, plaintext);
		if (plaintext.length() > 16) { // check for plaintext length
			cout << "For this Version of AES Cipher you can only enter a plaintext of size 128/ no less no more" << endl;
			goto again1;
		}
		else if (plaintext.length() < 16) { // check for plaintext length
			cout << "\t\t\t The text you entered is < 128 bits. what do you want to do: " << endl;padd:
			cout << "\t\t\t 1- Padd the plaintext to form a 128 bit plaintext\n\t\t\t 2- Enter text again yourself\n\t\t\t 3- Choose: ";
			cin >> choice;
			if (choice == 1) { //padding the plaintext
				for (int i = plaintext.length(); i < 16; i++) {
					plaintext += " ";
				}cin.ignore();
			}
			else if (choice == 2) {
				cin.ignore();
				goto again1;
			}
			else {
				cout << "\n\t\tInvalid Input. Try Again" << endl;
				cin.ignore(); goto padd;
			}
		}again:
		cout << "\t\t\t Enter the" << "\033[92m" << " key " << "\033[0m" << "to Encrypt Plaintext: "; // Taking key input
		getline(cin, in_key);
		cout << "\t\t\t Length of key entered: " << in_key.length() << endl;

		if (in_key.length() < 32) { //check for key length
			cout << "\t\t\t The key you entered is < 256 bits. what do you want to do: " << endl;
		choice:
			cout << "\t\t\t 1- Padd the key to form a 256 bit key\n\t\t\t 2- Enter key again yourself\n\t\t\t 3- Choose: ";
			cin >> choice;
			if (choice == 1) { // padding the key
				for (int i = in_key.length(); i < 32; i++) {
					in_key += " ";
				}cin.ignore();
			}
			else if (choice == 2) {
				cin.ignore();
				goto again;
			}
			else {
				cout << "\t\t\t Invalid Input. Please Try Entering Choice again.";
				goto choice;
			}
		}

		else if (in_key.length() > 32) {again2: // cutting the key to 256 bits if > 256 
			cout << "\t\tThe key you entered is grater than 32 bytes. What do you want to do: ";
			cout << "\n\t\t1- Enter a New Key\n\t\t2- Cut the key till 32 bytes\n\t\t3- Choose: ";
			cin >> choice;
			if (choice == 1) {
				cin.ignore();
				goto again;
			}
			else if (choice == 2) {
				string snd_key = "";
				for (int i = 0; i < 32; i++) {
					snd_key += in_key[i]; // cutting key and storing in a new one
				}
				in_key = snd_key;
			}
			else {
				cout << "\t\tInvalid Input. Please Try Again" << endl;
				goto again2;
			}
		}// Diisplaying user inputs
		cout << "\n\t\t --------------------------------------------------------------------------\n" << endl;
		cout << "\t\t\t Your Entrances\n\t\t\tPlaintext:" << plaintext << "\n\t\t\tKey: " << in_key << endl;
		cout << "\t\t Hex value for key: " << c1.str_to_hex(in_key) << endl;
		cout << "\t\t Length of hexed Key: " << c1.str_to_hex(in_key).length() << endl;
		cout << "\n\t\t --------------------------------------------------------------------------\n" << endl;
		quad_str = b1.quad_calc(c1.str_to_hex(in_key)); // calling fncton for 1st 08 w generation
		all_ws = w_s(quad_str); // funcion for creating all ws
		cout << "\n\t\t Printing Round Keys" << endl;
		round_keys = p1.key_generator(all_ws); // calling function for key generation
		for (int i = 0; i < 15; i++)
			cout << "\033[92m" << "\n\t\tkey[" << i << "]: " << round_keys[i] << "\033[0m"; // displaying keys

			encryption = All_rounder(c1.str_to_hex(plaintext), round_keys);
			cout << "\n\t\t Encrypted text: " << c1.str_to_hex(encryption) << endl; // Printing encrypted text
			decryption = Decryptor(round_keys, encryption, printer);
			cout << "\n\t\tDecrypted Text: " << c1.hex_to_str(decryption) << endl; // printing decrypted text
			/*cout << "\n\t\t Do you Want to\n\t\t1- Do another Encryption\n\t\t0- Quit Program\n\t\t";
			cin >> choice;
			if (choice == 1) {
				
				cin.ignore();
				goto onceagain;
			}
			else
				return 0;*/
			return 0;
	}
};

int main() {

	Main_Menu m1;
	m1.Menu();

	return 0;
}