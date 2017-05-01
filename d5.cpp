// d5.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <iostream>
#include <fstream>
#include <string>
#include <wdigest.h>
#include <vector>
#include <map>
#include <unordered_map>
#include <thread>

using namespace std;

static uint8_t S[16] = { 0xA, 0x9, 0xD, 0x6, 0xE, 0xB, 0x4, 0x5, 0xF, 0x1, 0x3, 0xC, 0x7, 0x0, 0x8, 0x2 };
static uint8_t S_rev[16] = { 0xd, 0x9, 0xf, 0xa, 0x6, 0x7, 0x3, 0xc, 0xe, 0x1, 0x0, 0x5, 0xb, 0x2, 0x4, 0x8 };

unordered_map<uint16_t, uint16_t>  matrix[65536];

uint16_t keys[65536] = { 0 };

double pres = 0.0001;

struct Gamma
{
	uint16_t b;
	double p;
};

vector<Gamma> List[7];


void swap_bits(uint8_t &a, uint8_t &b, uint8_t &a_i, uint8_t &b_i) 
{
	uint8_t tmp_b = ((b >> b_i) & 1) << a_i;	
	b = (b & ~(1 << b_i)) | (((a >> a_i) & 1) << b_i);
	a = (a & ~(1 << a_i)) | tmp_b;
}

uint16_t encrypt_round(uint16_t data, uint16_t key = 0)
{
	data ^= key;

	uint8_t data_blocks[4] = { 0 };
	uint16_t result = { 0 };

	for (uint8_t i = 0;i < 4;i++)
	{
		data_blocks[i] = (data >> (i * 4)) & 15;
	}

	for (uint8_t i = 0;i < 4;i++)
	{
		data_blocks[i] = S[data_blocks[i]];
	}

	for (uint8_t i = 0; i<4; i++){
		for (uint8_t j = i + 1; j < 4; j++)
		{
			swap_bits(data_blocks[i], data_blocks[j], j, i);
		}
	}

	for (uint8_t i = 0;i < 4;i++) {
		result += data_blocks[i] << (i * 4);
	}
	
	return result;
}

uint16_t decrypt_round(uint16_t data, uint16_t key = 0)
{
	uint16_t result = 0;
	uint8_t data_blocks[4] = { 0 };

	for (uint8_t i = 0;i < 4;i++)
	{
		data_blocks[i] = (data >> (i * 4)) & 15;
	}

	for (uint8_t i = 0; i<4; i++) {
		for (uint8_t j = i + 1; j < 4; j++)
		{
			swap_bits(data_blocks[i], data_blocks[j], j, i);
		}
	}

	for (uint8_t i = 0;i < 4;i++)
	{
		result += S_rev[data_blocks[i]] << (4 * i);
	}

	result ^= key;
	return result;
}

void encrypt_file(string infile, string outfile, string keyname)
{
	uint16_t r_keys[7] = { 0 };

	ifstream keyfile(keyname.c_str(), ios::in | ios::binary);
	ifstream datafile(infile.c_str(), ios::in | ios::binary);
	ofstream outdata(outfile.c_str(), ios::out | ios::binary);

	for (uint8_t i = 0;i < 7;i++)
	{
		keyfile.read((char*)&r_keys[i], sizeof(uint16_t));
	}

	keyfile.close();

	while (!datafile.eof()) {
		uint16_t data;
		datafile.read((char*)&data, sizeof(uint16_t));
		for (uint8_t r = 0;r < 6;r++)
		{
			data = encrypt_round(data, r_keys[r]);
		}
		data ^= r_keys[6];
		outdata.write((char*)&data, sizeof(uint16_t));
	}

	datafile.close();
	outdata.close();
}

void decrypt_file(string infile, string outfile, string keyname)
{
	uint16_t r_keys[7] = { 0 };

	ifstream keyfile(keyname.c_str(), ios::in | ios::binary);
	ifstream datafile(infile.c_str(), ios::in | ios::binary);
	ofstream outdata(outfile.c_str(), ios::out | ios::binary);
	
	for (uint8_t i = 0;i < 7;i++)
	{
		keyfile.read((char*)&r_keys[i], sizeof(uint16_t));
	}

	keyfile.close();

	while (!datafile.eof()) {
		uint16_t data;
		datafile.read((char*)&data, sizeof(uint16_t));
		data ^= r_keys[6];
			for (uint8_t r = 5;r < 6;r--)
			{
				data = decrypt_round(data, r_keys[r]);
			}
			outdata.write((char*)&data, sizeof(uint16_t));
	}

	datafile.close();
	outdata.close();
}

void to_first_round(uint16_t alpha) 
{
	for (uint16_t i = 0;i < 7;i++)
	{
		List[i].clear();
	}
	for (const auto& p : matrix[alpha]) 
	{
		if ((p.second / (1.0 * 65535)) > pres) 
		{
			Gamma tmp;
			tmp.b = p.first;
			tmp.p = p.second / (1.0 * 65535);
			List[1].push_back(tmp);
		}
	}
}

vector<Gamma> get_UB(vector<Gamma> prev)
{
	unordered_map<uint16_t, double> pre_result;
	for (auto alpha : prev) 
	{
		for (auto b : matrix[alpha.b]) 
		{
			pre_result[b.first] += alpha.p *((double)matrix[alpha.b][b.first] / (1.0 * 65535));
		}
	}
	vector<Gamma> result;
	for (auto tmp : pre_result) 
	{
		if (tmp.second > pres) 
		{
			Gamma t;
			t.b = tmp.first;
			t.p = tmp.second;
			result.push_back(t);
		}
	}
	return result;
}

void last_round_attack(uint16_t beta,string path = "data2/X")
{
	for (int i = 0;i < 65535;i++)
	{
		string name = path + to_string(i) + ".txt.bin";
		string name1 = path + "'" + to_string(i) + ".txt.bin";
		uint16_t data;
		uint16_t data1;
		ifstream plain(name.c_str(), ios::in | ios::binary);
		plain.read((char*)&data, sizeof(uint16_t));
		plain.close();
		ifstream plain1(name1.c_str(), ios::in | ios::binary);
		plain1.read((char*)&data1, sizeof(uint16_t));
		plain1.close();
		
		for (int key = 0;key < 65536;key++)
		{
			data ^= key;
			data1 ^= key;
			uint16_t dec1 = decrypt_round(data);			
			uint16_t dec2 = decrypt_round(data1);
			dec1 ^= beta;
			if (dec1 == dec2)
			{
				keys[key]++;
			}
		}
	}

	uint32_t max = 0;
	uint16_t ans = 0;
	for (int i = 0; i < 65536; i++)
	{
		if (keys[i] > 1)
		{			
			cout << hex << i << " " << keys[i] << endl;
		}
	}
}

void get_pa(int tmp)
{
	double max = 0;
	uint16_t b = 0;
	ofstream out("d6.txt" + to_string(tmp), ios::out);
	for (uint32_t a = (65536 / 4) * tmp;a < (65536 / 4)*(tmp + 1);a++)
	{
		cout << (int)a << endl;
		to_first_round(a);
		for (int i = 2;i < 7;i++)
		{
			List[i] = get_UB(List[i - 1]);
			if (i == 6) {
				for (auto j : List[i])
				{
					if (max < j.p) {
						max = j.p;
						b = j.b;
						out << "max = " << max << " a=" << (int)a << " b=" << (int)b << endl;
						cout  << "max = " << max << " a=" << (int)a << " b=" << (int)b << endl;
					}
				}
			}
		}
	}
	out.close();
}

void get_max_d6() {
	uint16_t S_my[65536];
	for (int x = 0;x < 65536;x++)
	{
		S_my[x] = encrypt_round(x);
	}

	for (int a = 0;a < 65536;a++)
	{
		for (int x = 0; x < 65536; x++)
		{
			matrix[a][S_my[x ^ a] ^ S_my[x]]++;
		}
	}
	get_pa(0);
	get_pa(1);
	get_pa(2);
	get_pa(3);
	//thread a0(get_pa,0);
	//thread a1(get_pa, 1);
	//thread a2(get_pa, 2);
	//thread a3(get_pa, 3);

	//a0.join();
	//a1.join();
	//a2.join();
	//a3.join();
}

void make_stat(uint16_t alpha, string path = "data2/X")
{
	for (int i = 0;i < 65535;i++)
	{
		string file_name = path + to_string(i) + ".txt";
		ofstream out(file_name.c_str(), ios::out | ios::binary);
		uint16_t data = i;
		out.write((char*)&data, sizeof(uint16_t));
		out.close();
		string file_name1 = path + "'" + to_string(i) + ".txt";
		ofstream out1(file_name1.c_str(), ios::out | ios::binary);
		uint16_t data1 = i ^ alpha;
		out1.write((char*)&data1, sizeof(uint16_t));
		out1.close();
	}
}


int main()
{
	//get_max_d6();
	//make_stat(1280);
	//last_round_attack(34944);

	system("PAUSE");
	return 0;
}