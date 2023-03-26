/*
The MIT License (MIT)

Copyright (C) 2023 Ir.Ts. Musnazril Bin Mustaq Khan

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

#include <iostream>

unsigned char* buffer_;
unsigned int buffer_size_;
unsigned long data_length_digits_[4];
unsigned long h_[8];


unsigned char mask_8bit(unsigned char x) { 
    return x & 0xff;
}

unsigned long mask_32bit(unsigned long x) { 
    return x & 0xffffffff;
}

const unsigned long add_constant[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 };

const unsigned long initial_message_digest[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372,
                                            0xa54ff53a, 0x510e527f, 0x9b05688c,
                                            0x1f83d9ab, 0x5be0cd19 };

unsigned long ch(unsigned long x, unsigned long y, unsigned long z) {
    return (x & y) ^ ((~x) & z);
}

unsigned long maj(unsigned long x, unsigned long y, unsigned long z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

unsigned long rotr(unsigned long x, unsigned char n) {
    return mask_32bit((x >> n) | (x << (32 - n)));
}

unsigned long bsig0(unsigned long x) {
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
}

unsigned long bsig1(unsigned long x) {
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
}

unsigned long shr(unsigned long x, unsigned char n) {
    return x >> n;
}

unsigned long ssig0(unsigned long x) {
    return rotr(x, 7) ^ rotr(x, 18) ^ shr(x, 3);
}

unsigned long ssig1(unsigned long x) {
    return rotr(x, 17) ^ rotr(x, 19) ^ shr(x, 10);
}

void hash256_block(unsigned long* message_digest, const unsigned char* data) {

    unsigned long w[64];

    for (unsigned char i = 0; i < 16; ++i) {
        w[i] = (static_cast<unsigned long>(mask_8bit(*(data + i * 4))) << 24) |
            (static_cast<unsigned long>(mask_8bit(*(data + i * 4 + 1))) << 16) |
            (static_cast<unsigned long>(mask_8bit(*(data + i * 4 + 2))) << 8) |
            (static_cast<unsigned long>(mask_8bit(*(data + i * 4 + 3))));
    }

    for (unsigned char i = 16; i < 64; ++i) {
        w[i] = mask_32bit(ssig1(w[i - 2]) + w[i - 7] + ssig0(w[i - 15]) +
            w[i - 16]);
    }

    unsigned long a = *message_digest;
    unsigned long b = *(message_digest + 1);
    unsigned long c = *(message_digest + 2);
    unsigned long d = *(message_digest + 3);
    unsigned long e = *(message_digest + 4);
    unsigned long f = *(message_digest + 5);
    unsigned long g = *(message_digest + 6);
    unsigned long h = *(message_digest + 7);

    for (unsigned char i = 0; i < 64; ++i) {
        unsigned long temp1 = h + bsig1(e) + ch(e, f, g) + add_constant[i] + w[i];
        unsigned long temp2 = bsig0(a) + maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = mask_32bit(d + temp1);
        d = c;
        c = b;
        b = a;
        a = mask_32bit(temp1 + temp2);
    }
    *message_digest += a;
    *(message_digest + 1) += b;
    *(message_digest + 2) += c;
    *(message_digest + 3) += d;
    *(message_digest + 4) += e;
    *(message_digest + 5) += f;
    *(message_digest + 6) += g;
    *(message_digest + 7) += h;

    for (unsigned char i = 0; i < 8; ++i) {
        *(message_digest + i) = mask_32bit(*(message_digest + i));
    }
}


void add_to_data_length(unsigned long n) {
    unsigned long carry = n;

    for (int i = 0; i < 4 && carry != 0; ++i) {
        data_length_digits_[i] += carry;
        carry = data_length_digits_[i] >> 16;
        data_length_digits_[i] &= 0xFFFF;
    }
}


void write_data_bit_length(unsigned char* begin) {

    unsigned long data_bit_length_digits[4];
        for (int i = 0; i < 4; ++i) {
        data_bit_length_digits[i] = data_length_digits_[i];
    }

    // convert byte length to bit length (multiply 8 or shift 3 times left)
    unsigned long carry = 0;
    for (unsigned char i = 0; i < 4; ++i) {
        unsigned long before_val = data_bit_length_digits[i];
        data_bit_length_digits[i] = (data_bit_length_digits[i] << 3) | carry;
        data_bit_length_digits[i] &= 0xFFFF;
        carry = (before_val >> 13) & 0xFFFF;
    }

    // write data_bit_length
    for (int i = 3; i >= 0; --i) {
        *begin++ = data_bit_length_digits[i] >> 8;
        *begin++ = data_bit_length_digits[i] & 0xFF;
    }
}

void get_hash_bytes(unsigned char* data_start, unsigned char* data_end) {
    const unsigned long* h_ptr = h_;

    for (int i = 0; i < 8 && data_start != data_end; ++i) {
        unsigned long current_val = *(h_ptr++);
        for (int shift = 24; shift >= 0 && data_start != data_end; shift -= 8) {
            *(data_start++) = static_cast<unsigned char>((current_val >> shift) & 0xFF);
        }
    }
}


void SHA256_Init() {
    buffer_size_ = 0;
    buffer_ = nullptr;
    
    for (int i = 0; i < 4; ++i) {
        data_length_digits_[i] = 0ul;
    }

    for (int i = 0; i < 8; ++i) {
        h_[i] = initial_message_digest[i];
    }
}


void SHA256_Process(const unsigned char* data_start, const unsigned char* data_end) {

    const unsigned int length = static_cast<unsigned int>(data_end - data_start);
    add_to_data_length(static_cast<unsigned long>(length));

    unsigned char* new_buffer = new unsigned char[buffer_size_ + length];
    for (int i = 0; i < buffer_size_; ++i) {
        new_buffer[i] = buffer_[i];
    }

    int data_length = data_end - data_start;
    for (int i = 0; i < data_length; ++i) {
        new_buffer[buffer_size_ + i] = data_start[i];
    }

    delete[] buffer_;
    buffer_ = new_buffer;
    buffer_size_ += length;

    unsigned char i = 0;
    for (; i + 64 <= buffer_size_; i += 64) {
        hash256_block(h_, buffer_ + i);
    }

    buffer_size_ -= i;
    for (int j = 0; j < buffer_size_; ++j) {
        buffer_[j] = buffer_[j + i];
    }
}

void SHA256_Finish() {
    
    unsigned char temp[64];
    for (int i = 0; i < 64; ++i) {
        temp[i] = static_cast<unsigned char>(0);
    }

    unsigned char remains = buffer_size_;
    for (int i = 0; i < buffer_size_; ++i) {
        temp[i] = buffer_[i];
    }

    // Add padding byte
    temp[remains] = 0x80;

    if (remains > 55) {
        for (int i = remains + 1; i < 64; ++i) {
            temp[i] = static_cast<unsigned char>(0);
        }

        hash256_block(h_, temp);
        for (int i = 0; i < 64 - 4; ++i) {
            temp[i] = static_cast<unsigned char>(0);
        }
    }
    else {
        for (int i = remains + 1; i < 64 - 4; ++i) {
            temp[i] = static_cast<unsigned char>(0);
        }
    }

    write_data_bit_length(&(temp[56]));

    hash256_block(h_, temp);
}


std::string kernel_sha256(unsigned char data[], unsigned char size_data) {

    std::string hex_str;
    char hex_char[64];
    unsigned char hashed[32];
    static const char hex_digit[] = "0123456789abcdef";
     
    SHA256_Init();
    SHA256_Process(data, (data + size_data));
    SHA256_Finish();
    
    get_hash_bytes(hashed, (hashed + 32));
    
    //convert hex char to hex string
    for (int i = 0; i < 32; ++i) {
        hex_char[i * 2] = hex_digit[hashed[i] >> 4];
        hex_char[i * 2 + 1] = hex_digit[hashed[i] & 0xf];
    }
    hex_str = std::string(hex_char, 64);

    return hex_str;
}

int main(int argc, char** argv) {
    std::string hashed_out;

    //precode input for testing
    unsigned char data[] = { 'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd'};
    unsigned char size_data = sizeof(data);

    hashed_out = kernel_sha256(data, size_data);

    //print result
    std::cout << hashed_out << std::endl;
    
    return 0;
}
