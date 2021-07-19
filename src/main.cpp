//
// Copyright 2021 Yubico AB
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

#include <stdio.h>
#include <fstream>
#include <stdexcept>
#include <string>
#include <regex>
#include <vector>
#include <openssl/cmac.h>
#include <openssl/rand.h>

using namespace std;

// map MSVC functions to posix functions
#ifdef _MSC_VER
#define strcasecmp _strcmpi
#define strncasecmp _strnicmp
#endif

//
// KDF Definitions
//
#define KDF_CMAC_SIZE 16 /* 16 bytes, 128 bits */
#define KDF_LABEL_LEN 4  /* from SP800-108 spec */
#define KDF_CTX_LEN 10   /* 1st 10 bytes of Global Platform Div Data */

// KDF Output Encoding
enum KDF_ENC
{
    KDF_ENC_BIN = 0x00,
    KDF_ENC_NUM = 0x01
};

// KDF Labels
const unsigned char KDF_LABEL_DAK[] =         { 0x00, 0x00, 0x00, 0x01 };
const unsigned char KDF_LABEL_DMK[] =         { 0x00, 0x00, 0x00, 0x02 };
const unsigned char KDF_LABEL_DEK[] =         { 0x00, 0x00, 0x00, 0x03 };
const unsigned char KDF_LABEL_PIV_ADMIN[] =   { 0x00, 0x00, 0x00, 0x04 };
const unsigned char KDF_LABEL_PIV_PIN[] =     { 0x00, 0x00, 0x00, 0x06 };
const unsigned char KDF_LABEL_PIV_PUK[] =     { 0x00, 0x00, 0x00, 0x07 };
const unsigned char KDF_LABEL_CONFIG_LOCK[] = { 0x00, 0x00, 0x00, 0x10 };
const unsigned char KDF_LABEL_U2F_PIN[] =     { 0x00, 0x00, 0x00, 0x80 };
const unsigned char KDF_LABEL_OPGP_PW1[] =    { 0x00, 0x00, 0x00, 0x81 };
const unsigned char KDF_LABEL_OPGP_PW3[] =    { 0x00, 0x00, 0x00, 0x82 };
const unsigned char KDF_LABEL_OPGP_ADMIN[] =  { 0x00, 0x00, 0x00, 0x83 };
const unsigned char KDF_LABEL_YUBIOATH[] =    { 0x00, 0x00, 0x00, 0x84 };
const unsigned char KDF_LABEL_OATHCRED[] =    { 0x00, 0x00, 0x00, 0xC0 };

// Defaults
const char *DEFAULT_KEY = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const char *DEFAULT_PREFIX = "000000000000";

// AES_CMAC_KDF:
//
// Key derivation function (KDF) based on an AES256 CMAC.
// The algorithm is defined in NIST SP800-108 (revised, 2009).
//
// It generates an arbitrary amount of key material from a 32 byte master secret
// using the Counter Mode variant of the KDF.
//
// Parameters:
//   masterKey: 32 byte, (256 bit) shared secret
//    label:     identifier for the generated MAC (key), KDF_LABEL_LEN bytes
//   ctxt:      context data read from the key, KDF_CTX_LEN bytes
//    out:       pointer to a generated output
//    outLen:    desired length in bytes of the output
//
// Notes:
//
//   The maximum output length (bytes) is limited to 255 * KDF_CMAC_SIZE,
//   since the the counter field is a single byte integer.
//
//   The caller is responsible for allocating and freeing memory for generated output.
//

#pragma pack(push, 1) // pack struct along byte boundaries

typedef struct KDF_DATA
{ // the data field for the CMAC KDF
    uint8_t counter;
    unsigned char label[KDF_LABEL_LEN];
    unsigned char separator; // single byte, value is always 0x00
    unsigned char context[KDF_CTX_LEN];
    unsigned char macBits[2]; // bits of output in network byte order
} KDF_DATA;

#pragma pack(pop)

void AES_CMAC_KDF(const uint8_t *masterKey, const uint8_t *label,
                  const uint8_t *ctxt, uint8_t *out, size_t outLen)
{
    KDF_DATA data;
    size_t numBits = outLen * 8;
    CMAC_CTX *ctx = NULL;

    data.separator = (unsigned char)0x00;

    // The macBits field is the number of output bits in Network Byte Order.
    // Depending on the endianness of the host, this number may need to be
    // converted to network byte order after its size has been calculated.

    data.macBits[0] = (uint8_t)(numBits >> 8);
    data.macBits[1] = (uint8_t)numBits;

    memcpy(data.label, label, KDF_LABEL_LEN);
    memcpy(data.context, ctxt, KDF_CTX_LEN);

    // Each iteration generates KDF_CMAC_SIZE bytes of MAC data, so the number of
    // iterations is the ceiling of the number of desired output bytes divided by KDF_CMAC_SIZE.

    size_t numIterations = outLen / KDF_CMAC_SIZE; // number of full blocks of output

    if (outLen % KDF_CMAC_SIZE) // add one if a partial block remains
        numIterations = numIterations + 1;

    uint8_t mac[KDF_CMAC_SIZE]; // same as block size for the AES cipher
    size_t macLen = KDF_CMAC_SIZE;
    size_t bytesRemaining = outLen;

    ctx = CMAC_CTX_new();

    for (int i = 0; i < numIterations; i++)
    {
        data.counter = i + 1;

        CMAC_Init(ctx, masterKey, 32, EVP_aes_256_cbc(), NULL);
        CMAC_Update(ctx, &data, sizeof(data));
        CMAC_Final(ctx, mac, &macLen);

        if (bytesRemaining >= KDF_CMAC_SIZE)
        {
            memcpy(out + KDF_CMAC_SIZE * i, mac, KDF_CMAC_SIZE);
            bytesRemaining -= KDF_CMAC_SIZE;
        }
        else
        {
            memcpy(out + KDF_CMAC_SIZE * i, mac, bytesRemaining);
            bytesRemaining = 0;
        }
    }

    CMAC_CTX_free(ctx);
}

//
// Helpers
//

void printBuffer(const unsigned char *buf, size_t len)
{
    for (int i = 0; i < len; i++)
    {
        printf("%02x", buf[i]);
    }
}

string encodePrintable(const unsigned char *buf, size_t len)
{
    string result;

    for (size_t i = 0; i < len; i++)
    {
        result += static_cast<char>('0' + (buf[i] % 10));
    }

    return result;
}

void printKdf(const uint8_t key[32], const char* label_name, const uint8_t label[4], const uint8_t div_data[10], size_t output_len, KDF_ENC encoding) {
    vector<uint8_t> output = vector<uint8_t>(output_len);

    AES_CMAC_KDF(key, label, div_data, output.data(), output_len);
    printf("Label: %s (", label_name);
    printBuffer(label, 4);
    if (encoding == KDF_ENC_BIN)
    {
        printf("), Value (%zd bytes, Binary): ", output_len);
        printBuffer(output.data(), output_len);
    }
    else
    {
        printf("), Value (%zd chars, Number): %s", output_len, encodePrintable(output.data(), output_len).c_str());
    }
    printf("\n");
}

void decodeHex(string& src, vector<uint8_t> dst) {
    char code[3] = {0};

    for (int i = 0; i < src.length(); i += 2)
    {
        code[0] = src.at(i);
        code[1] = src.at(i + 1);
        dst.push_back((uint8_t)strtoul(code, nullptr, 16));
    }
}

void readArguments(int argc, char **argv,
                   uint8_t prefix[6],
                   uint8_t serial[4],
                   uint8_t bmk[32])
{
    vector<uint8_t> vec_bmk;
    vector<uint8_t> vec_prefix;
    vector<uint8_t> vec_serial;
    regex rgx_bmk("^[A-Fa-f0-9]{64}$");
    regex rgx_prefix("^[A-Fa-f0-9]{12}$");
    regex rgx_serial("^[0-9]{1,10}$");
    bool fPrefix = false;
    bool fSerial = false;
    bool fKey = false;

    const char *p_temp = strrchr(argv[0], '\\');
    string app_name = p_temp ? p_temp + 1 : argv[0];

    string str_bmk = DEFAULT_KEY;
    string str_prefix = DEFAULT_PREFIX;
    string str_serial;

    for (int i = 1; i < argc; i++)
    {
        if (!strcasecmp(argv[i], "-h"))
        {
            printf("%s\n"
                   "  -h          - help"
                   "  -p|--prefix - key prefix (12 hex digits) or 'default' or 'random'\n"
                   "  -k|--key    - master key (64 hex digits) or 'default' or 'random' or filename from which to derive keys\n"
                   "  -s]--serial - serial number (decimal number) or 'random'\n",
                   app_name.c_str());

            exit(0);
        }
        else if (!strcasecmp(argv[i], "--prefix") || !strcasecmp(argv[i], "-p"))
        {
            if (fPrefix)
            {
                throw invalid_argument("Duplicate argument for prefix.");
            }
            else if (i + 1 < argc)
            {
                str_prefix = argv[++i];
                fPrefix = true;
            }
            else
            {
                throw invalid_argument(string(argv[i]) + " requires an argument.");
            }
        }
        else if (!strcasecmp(argv[i], "--key") || !strcasecmp(argv[i], "-k"))
        {
            if (fKey)
            {
                throw invalid_argument("Duplicate argument for key.");
            }
            else if (i + 1 < argc)
            {
                str_bmk = argv[++i];
                fKey = true;
            }
            else
            {
                throw invalid_argument(string(argv[i]) + " requires an argument.");
            }
        }
        else if (!strcasecmp(argv[i], "--serial") || !strcasecmp(argv[i], "-s"))
        {
            if (fSerial)
            {
                throw invalid_argument("Duplicate argument for serial.");
            }
            else if (i + 1 < argc)
            {
                str_serial = argv[++i];
                fSerial = true;
            }
            else
            {
                throw invalid_argument(string(argv[i]) + " requires an argument.");
            }
        }
    }

    if (!strcasecmp(str_prefix.c_str(), "default"))
    {
        str_prefix = DEFAULT_PREFIX;
    }
    
    if (!strcasecmp(str_prefix.c_str(), "random"))
    {
        vec_prefix.resize(6);
        RAND_bytes(const_cast<unsigned char*>(vec_prefix.data()), 6);
    }
    else if (!regex_match(str_prefix, rgx_prefix))
    {
        throw invalid_argument("Prefix must be 12 hex digits");
    }
    else {
        char code[3] = {0};

        for (int i = 0; i < str_prefix.length(); i += 2)
        {
            code[0] = str_prefix.at(i);
            code[1] = str_prefix.at(i + 1);
            vec_prefix.push_back((uint8_t)strtoul(code, nullptr, 16));
        }
    }

   if (vec_prefix.size() != 6)
    {
        throw invalid_argument("Prefix must be 6 bytes");
    }

    std::copy(vec_prefix.begin(), vec_prefix.end(), prefix);

    if (!strcasecmp(str_bmk.c_str(), "default"))
    {
        str_bmk = DEFAULT_KEY;
    }
    else if (!regex_match(str_bmk, rgx_bmk) && strcasecmp(str_bmk.c_str(), "random"))
    {        
        // interpret argument as file
        ifstream is(str_bmk);
        char buffer[256];

        if (is.getline(buffer, sizeof(buffer)).fail())
        {
            throw runtime_error(string("Could not read bmk from file") + str_bmk + ".");
        }

        str_bmk = buffer;
    }

    if (!strcasecmp(str_bmk.c_str(), "random"))
    {
        vec_bmk.resize(32);
        RAND_bytes(const_cast<unsigned char *>(vec_bmk.data()), 32);
    }
    else 
    {
        char code[3] = {0};

        for (int i = 0; i < str_bmk.length(); i += 2)
        {
            code[0] = str_bmk.at(i);
            code[1] = str_bmk.at(i + 1);
            vec_bmk.push_back((uint8_t)strtoul(code, nullptr, 16));
        }
    }

    if (vec_bmk.size() != 32)
    {
        throw invalid_argument("This application requires a master key, encoded in 64 hex digits");
    }

    std::copy(vec_bmk.begin(), vec_bmk.end(), bmk);

    if (!strcasecmp(str_serial.c_str(), "random"))
    {
        vec_serial.resize(4);
        RAND_bytes(const_cast<unsigned char*>(vec_serial.data()), 4);
    }
    else if (!regex_match(str_serial, rgx_serial))
    {
        throw invalid_argument("Serial must be a positive decimal number");
    }
    else {

        uint32_t serial = strtoul(str_serial.c_str(), NULL, 10);

        vec_serial.push_back(serial >> 24);
        vec_serial.push_back(serial >> 16);
        vec_serial.push_back(serial >> 8);
        vec_serial.push_back(serial);
    }

    std::copy(vec_serial.begin(), vec_serial.end(), serial);
}

/* Main CLI */
int main(int argc, char *argv[])
{
    uint8_t div_data[10] = {0};
    uint8_t bmk[32] = {0};

    try
    {
        readArguments(argc, argv, div_data, div_data + 6, bmk);

        printf("Using BMK: ");
        printBuffer(bmk, sizeof(bmk));
        printf("\n");

        printf("Using Diversification Data: ");
        printBuffer(div_data, sizeof(div_data));
        printf("\n\n");

        printKdf(bmk, "ISD_DAK", KDF_LABEL_DAK, div_data, 16, KDF_ENC_BIN);
        printKdf(bmk, "ISD_DMK", KDF_LABEL_DMK, div_data, 16, KDF_ENC_BIN);
        printKdf(bmk, "ISD_DEK", KDF_LABEL_DEK, div_data, 16, KDF_ENC_BIN);
        printKdf(bmk, "PIV_ADMIN", KDF_LABEL_PIV_ADMIN, div_data, 24, KDF_ENC_BIN);
        printKdf(bmk, "PIV_PIN", KDF_LABEL_PIV_PIN, div_data, 6, KDF_ENC_NUM);
        printKdf(bmk, "PIV_PUK", KDF_LABEL_PIV_PUK, div_data, 8, KDF_ENC_NUM);
        printKdf(bmk, "CONFIG_LOCK", KDF_LABEL_CONFIG_LOCK, div_data, 16, KDF_ENC_BIN);
        printKdf(bmk, "U2F_PIN", KDF_LABEL_U2F_PIN, div_data, 6, KDF_ENC_NUM);
        printKdf(bmk, "OPGP_PW1", KDF_LABEL_OPGP_PW1, div_data, 6, KDF_ENC_NUM);
        printKdf(bmk, "OPGP_PW3", KDF_LABEL_OPGP_PW3, div_data, 8, KDF_ENC_NUM);
        printKdf(bmk, "OPGP_ADMIN", KDF_LABEL_OPGP_ADMIN, div_data, 16, KDF_ENC_BIN);
        printKdf(bmk, "OATH_ADMIN", KDF_LABEL_YUBIOATH, div_data, 16, KDF_ENC_BIN);
        printKdf(bmk, "OATH_CRED0", KDF_LABEL_OATHCRED, div_data, 20, KDF_ENC_BIN);        
    }
    catch(std::exception e) {
        printf("Error occurred: %s", e.what());
        return -1;
    }

    return 0;
}
