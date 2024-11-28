#include <AES (2).h>
#include <vector>
#include <sstream>
#include <stdexcept>
#include <iomanip>

AES::AES(const AESKeyLength keyLength) {
    switch (keyLength) {
    case AESKeyLength::AES_128:
        this->Nk = 4;
        this->Nr = 10;
        break;
    case AESKeyLength::AES_192:
        this->Nk = 6;
        this->Nr = 12;
        break;
    case AESKeyLength::AES_256:
        this->Nk = 8;
        this->Nr = 14;
        break;
    }
}

unsigned char* AES::EncryptECB(const unsigned char in[], unsigned int inLen,
    const unsigned char key[]) {
    CheckLength(inLen);
    unsigned char* out = new unsigned char[inLen];
    unsigned char* roundKeys = new unsigned char[4 * Nb * (Nr + 1)];
    KeyExpansion(key, roundKeys);
    for (unsigned int i = 0; i < inLen; i += blockBytesLen) {
        EncryptBlock(in + i, out + i, roundKeys);
    }

    delete[] roundKeys;

    return out;
}

unsigned char* AES::DecryptECB(const unsigned char in[], unsigned int inLen,
    const unsigned char key[]) {
    CheckLength(inLen);
    unsigned char* out = new unsigned char[inLen];
    unsigned char* roundKeys = new unsigned char[4 * Nb * (Nr + 1)];
    KeyExpansion(key, roundKeys);
    for (unsigned int i = 0; i < inLen; i += blockBytesLen) {
        DecryptBlock(in + i, out + i, roundKeys);
    }

    delete[] roundKeys;

    return out;
}

unsigned char* AES::EncryptCBC(const unsigned char in[], unsigned int inLen,
    const unsigned char key[],
    const unsigned char* iv) {
    CheckLength(inLen);
    unsigned char* out = new unsigned char[inLen];
    unsigned char block[blockBytesLen];
    unsigned char* roundKeys = new unsigned char[4 * Nb * (Nr + 1)];
    KeyExpansion(key, roundKeys);
    memcpy(block, iv, blockBytesLen);
    for (unsigned int i = 0; i < inLen; i += blockBytesLen) {
        XorBlocks(block, in + i, block, blockBytesLen);
        EncryptBlock(block, out + i, roundKeys);
        memcpy(block, out + i, blockBytesLen);
    }

    delete[] roundKeys;

    return out;
}

unsigned char* AES::DecryptCBC(const unsigned char in[], unsigned int inLen,
    const unsigned char key[],
    const unsigned char* iv) {
    CheckLength(inLen);
    unsigned char* out = new unsigned char[inLen];
    unsigned char block[blockBytesLen];
    unsigned char* roundKeys = new unsigned char[4 * Nb * (Nr + 1)];
    KeyExpansion(key, roundKeys);
    memcpy(block, iv, blockBytesLen);
    for (unsigned int i = 0; i < inLen; i += blockBytesLen) {
        DecryptBlock(in + i, out + i, roundKeys);
        XorBlocks(block, out + i, out + i, blockBytesLen);
        memcpy(block, in + i, blockBytesLen);
    }

    delete[] roundKeys;

    return out;
}

unsigned char* AES::EncryptCFB(const unsigned char in[], unsigned int inLen,
    const unsigned char key[],
    const unsigned char* iv) {
    CheckLength(inLen);
    unsigned char* out = new unsigned char[inLen];
    unsigned char block[blockBytesLen];
    unsigned char encryptedBlock[blockBytesLen];
    unsigned char* roundKeys = new unsigned char[4 * Nb * (Nr + 1)];
    KeyExpansion(key, roundKeys);
    memcpy(block, iv, blockBytesLen);
    for (unsigned int i = 0; i < inLen; i += blockBytesLen) {
        EncryptBlock(block, encryptedBlock, roundKeys);
        XorBlocks(in + i, encryptedBlock, out + i, blockBytesLen);
        memcpy(block, out + i, blockBytesLen);
    }

    delete[] roundKeys;

    return out;
}

unsigned char* AES::DecryptCFB(const unsigned char in[], unsigned int inLen,
    const unsigned char key[],
    const unsigned char* iv) {
    CheckLength(inLen);
    unsigned char* out = new unsigned char[inLen];
    unsigned char block[blockBytesLen];
    unsigned char encryptedBlock[blockBytesLen];
    unsigned char* roundKeys = new unsigned char[4 * Nb * (Nr + 1)];
    KeyExpansion(key, roundKeys);
    memcpy(block, iv, blockBytesLen);
    for (unsigned int i = 0; i < inLen; i += blockBytesLen) {
        EncryptBlock(block, encryptedBlock, roundKeys);
        XorBlocks(in + i, encryptedBlock, out + i, blockBytesLen);
        memcpy(block, in + i, blockBytesLen);
    }

    delete[] roundKeys;

    return out;
}

void AES::CheckLength(unsigned int len) {
    if (len % blockBytesLen != 0) {
        throw std::length_error("Plaintext length must be divisible by " + std::to_string(blockBytesLen));
    }
}
bool AES::CheckLength1(unsigned int len) {
    if (len % blockBytesLen != 0) {
        return false;
    }
    return true;
}
void removeElements(std::vector<unsigned char>& myVector, int numToRemove) {
    if (numToRemove <= 0 || myVector.empty()) {
        return;
    }
    myVector.erase(myVector.end() - numToRemove * 2, myVector.end());
}

std::vector<unsigned char> AddPadding(const std::vector<unsigned char>& plaintext, int blockBytesLen) {
    std::vector<unsigned char> paddedText = plaintext;
    unsigned int paddingLen = blockBytesLen - (plaintext.size() % blockBytesLen);
    if (paddingLen != blockBytesLen) {
        for (unsigned int i = 0; i < paddingLen - 1; ++i) { ////////////////
            paddedText.push_back(0x00);  // Add 0x00 padding
        }
        paddedText.push_back(paddingLen);
    }
    return paddedText;
}

void AES::EncryptBlock(const unsigned char in[], unsigned char out[], unsigned char* roundKeys) {
    unsigned char state[4][Nb];
    unsigned int i, j, round;

    for (i = 0; i < 4; i++) {
        for (j = 0; j < Nb; j++) {
            state[i][j] = in[i + 4 * j];
        }
    }

    AddRoundKey(state, roundKeys);

    for (round = 1; round <= Nr - 1; round++) {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(state, roundKeys + round * 4 * Nb);
    }

    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, roundKeys + Nr * 4 * Nb);

    for (i = 0; i < 4; i++) {
        for (j = 0; j < Nb; j++) {
            out[i + 4 * j] = state[i][j];
        }
    }
}

void AES::DecryptBlock(const unsigned char in[], unsigned char out[],
    unsigned char* roundKeys) {
    unsigned char state[4][Nb];
    unsigned int i, j, round;

    for (i = 0; i < 4; i++) {
        for (j = 0; j < Nb; j++) {
            state[i][j] = in[i + 4 * j];
        }
    }

    AddRoundKey(state, roundKeys + Nr * 4 * Nb);

    for (round = Nr - 1; round >= 1; round--) {
        InvSubBytes(state);
        InvShiftRows(state);
        AddRoundKey(state, roundKeys + round * 4 * Nb);
        InvMixColumns(state);
    }

    InvSubBytes(state);
    InvShiftRows(state);
    AddRoundKey(state, roundKeys);

    for (i = 0; i < 4; i++) {
        for (j = 0; j < Nb; j++) {
            out[i + 4 * j] = state[i][j];
        }
    }
}
/// //////////////

void AES::SubBytes(unsigned char state[4][Nb]) { // sbox
    unsigned int i, j;
    unsigned char t;
    for (i = 0; i < 4; i++) {
        for (j = 0; j < Nb; j++) {
            t = state[i][j];
            state[i][j] = sbox[t / 16][t % 16];
        }
    }
}

//////////////
void AES::ShiftRow(unsigned char state[4][Nb], unsigned int i,
    unsigned int n)  // shift row i on n positions
{
    unsigned char tmp[Nb];
    for (unsigned int j = 0; j < Nb; j++) {
        tmp[j] = state[i][(j + n) % Nb];
    }
    memcpy(state[i], tmp, Nb * sizeof(unsigned char));
}

void AES::ShiftRows(unsigned char state[4][Nb]) {
    ShiftRow(state, 1, 1);
    ShiftRow(state, 2, 2);
    ShiftRow(state, 3, 3);
}
///////////////////


unsigned char AES::xtime(unsigned char b)  // multiply on x
{
    return (b << 1) ^ (((b >> 7) & 1) * 0x1b);
}


///////////////////////////////

void AES::MixColumns(unsigned char state[4][Nb]) {
    unsigned char temp_state[4][Nb];

    for (size_t i = 0; i < 4; ++i) {
        memset(temp_state[i], 0, 4);
    }

    for (size_t i = 0; i < 4; ++i) {
        for (size_t k = 0; k < 4; ++k) {
            for (size_t j = 0; j < 4; ++j) {
                if (CMDS[i][k] == 1)
                    temp_state[i][j] ^= state[k][j];
                else
                    temp_state[i][j] ^= GF_MUL_TABLE[CMDS[i][k]][state[k][j]];
            }
        }
    }

    for (size_t i = 0; i < 4; ++i) {
        memcpy(state[i], temp_state[i], 4);
    }
}
///////////////////////////////

void AES::AddRoundKey(unsigned char state[4][Nb], unsigned char* key) {
    unsigned int i, j;
    for (i = 0; i < 4; i++) {
        for (j = 0; j < Nb; j++) {
            state[i][j] = state[i][j] ^ key[i + 4 * j];
        }
    }
}
///////////////////////////////

void AES::SubWord(unsigned char* a) {
    int i;
    for (i = 0; i < 4; i++) {
        a[i] = sbox[a[i] / 16][a[i] % 16];
    }
}

void AES::RotWord(unsigned char* a) {
    unsigned char c = a[0];
    a[0] = a[1];
    a[1] = a[2];
    a[2] = a[3];
    a[3] = c;
}

void AES::XorWords(unsigned char* a, unsigned char* b, unsigned char* c) {
    int i;
    for (i = 0; i < 4; i++) {
        c[i] = a[i] ^ b[i];
    }
}

void AES::Rcon(unsigned char* a, unsigned int n) {
    unsigned int i;
    unsigned char c = 1;
    for (i = 0; i < n - 1; i++) {
        c = xtime(c);
    }

    a[0] = c;
    a[1] = a[2] = a[3] = 0;
}

void AES::KeyExpansion(const unsigned char key[], unsigned char w[]) {
    unsigned char temp[4];
    unsigned char rcon[4];

    unsigned int i = 0;
    while (i < 4 * Nk) {
        w[i] = key[i];
        i++;
    }

    i = 4 * Nk;
    while (i < 4 * Nb * (Nr + 1)) {
        temp[0] = w[i - 4 + 0];
        temp[1] = w[i - 4 + 1];
        temp[2] = w[i - 4 + 2];
        temp[3] = w[i - 4 + 3];

        if (i / 4 % Nk == 0) {
            RotWord(temp);
            SubWord(temp);
            Rcon(rcon, i / (Nk * 4));
            XorWords(temp, rcon, temp);
        }
        else if (Nk > 6 && i / 4 % Nk == 4) {
            SubWord(temp);
        }

        w[i + 0] = w[i - 4 * Nk] ^ temp[0];
        w[i + 1] = w[i + 1 - 4 * Nk] ^ temp[1];
        w[i + 2] = w[i + 2 - 4 * Nk] ^ temp[2];
        w[i + 3] = w[i + 3 - 4 * Nk] ^ temp[3];
        i += 4;
    }
}

void AES::InvSubBytes(unsigned char state[4][Nb]) {
    unsigned int i, j;
    unsigned char t;
    for (i = 0; i < 4; i++) {
        for (j = 0; j < Nb; j++) {
            t = state[i][j];
            state[i][j] = inv_sbox[t / 16][t % 16];
        }
    }
}

void AES::InvMixColumns(unsigned char state[4][Nb]) {
    unsigned char temp_state[4][Nb];

    for (size_t i = 0; i < 4; ++i) {
        memset(temp_state[i], 0, 4);
    }

    for (size_t i = 0; i < 4; ++i) {
        for (size_t k = 0; k < 4; ++k) {
            for (size_t j = 0; j < 4; ++j) {
                temp_state[i][j] ^= GF_MUL_TABLE[INV_CMDS[i][k]][state[k][j]];
            }
        }
    }

    for (size_t i = 0; i < 4; ++i) {
        memcpy(state[i], temp_state[i], 4);
    }
}

void AES::InvShiftRows(unsigned char state[4][Nb]) {
    ShiftRow(state, 1, Nb - 1);
    ShiftRow(state, 2, Nb - 2);
    ShiftRow(state, 3, Nb - 3);
}

void AES::XorBlocks(const unsigned char* a, const unsigned char* b,
    unsigned char* c, unsigned int len) {
    for (unsigned int i = 0; i < len; i++) {
        c[i] = a[i] ^ b[i];
    }
}

void AES::printHexArray(unsigned char a[], unsigned int n) {
    for (unsigned int i = 0; i < n; i++) {
        printf("%02x ", a[i]);
    }
}

void AES::printHexVector(std::vector<unsigned char> a) {
    for (unsigned int i = 0; i < a.size(); i++) {
        printf("%02x", a[i]);
    }
}

std::vector<unsigned char> AES::ArrayToVector(unsigned char* a,
    unsigned int len) {
    std::vector<unsigned char> v(a, a + len * sizeof(unsigned char));
    return v;
}

unsigned char* AES::VectorToArray(std::vector<unsigned char>& a) {
    return a.data();
}

std::vector<unsigned char> AES::EncryptECB(std::vector<unsigned char> in,
    std::vector<unsigned char> key) {
    if (!CheckLength1(in.size()))
    {
        in = AddPadding(in, 16);
    }
    unsigned char* out = EncryptECB(VectorToArray(in), (unsigned int)in.size(),
        VectorToArray(key));
    std::vector<unsigned char> v = ArrayToVector(out, in.size());
    delete[] out;
    return v;
}

std::vector<unsigned char> AES::DecryptECB(std::vector<unsigned char> in,
    std::vector<unsigned char> key) {
    unsigned char* out = DecryptECB(VectorToArray(in), (unsigned int)in.size(),
        VectorToArray(key));
    std::vector<unsigned char> v = ArrayToVector(out, (unsigned int)in.size());
    delete[] out;
    return v;
}

std::vector<unsigned char> AES::EncryptCBC(std::vector<unsigned char> in,
    std::vector<unsigned char> key,
    std::vector<unsigned char> iv) {
    if (!CheckLength1(in.size()))
    {
        in = AddPadding(in, 16);
    }
    unsigned char* out = EncryptCBC(VectorToArray(in), (unsigned int)in.size(),
        VectorToArray(key), VectorToArray(iv));
    std::vector<unsigned char> v = ArrayToVector(out, in.size());
    delete[] out;
    return v;
}

std::vector<unsigned char> AES::DecryptCBC(std::vector<unsigned char> in,
    std::vector<unsigned char> key,
    std::vector<unsigned char> iv) {
    unsigned char* out = DecryptCBC(VectorToArray(in), (unsigned int)in.size(),
        VectorToArray(key), VectorToArray(iv));
    std::vector<unsigned char> v = ArrayToVector(out, (unsigned int)in.size());
    delete[] out;
    return v;
}

std::vector<unsigned char> AES::EncryptCFB(std::vector<unsigned char> in,
    std::vector<unsigned char> key,
    std::vector<unsigned char> iv) {
    if (!CheckLength1(in.size()))
    {
        in = AddPadding(in, 16);
    }
    unsigned char* out = EncryptCFB(VectorToArray(in), (unsigned int)in.size(),
        VectorToArray(key), VectorToArray(iv));
    std::vector<unsigned char> v = ArrayToVector(out, in.size());
    delete[] out;
    return v;
}

std::vector<unsigned char> AES::DecryptCFB(std::vector<unsigned char> in,
    std::vector<unsigned char> key,
    std::vector<unsigned char> iv) {
    unsigned char* out = DecryptCFB(VectorToArray(in), (unsigned int)in.size(),
        VectorToArray(key), VectorToArray(iv));
    std::vector<unsigned char> v = ArrayToVector(out, (unsigned int)in.size());
    delete[] out;
    return v;
}

std::string VectorToHex(const std::vector<unsigned char>& input) {
    std::stringstream output;
    output << std::hex << std::setfill('0');
    for (size_t i = 0; i < input.size(); ++i) {
        output << std::setw(2) << static_cast<unsigned int>(input[i]);
    }
    return output.str();
}


int main() {
    // IF THE PLAINTEXT IS NOT DIVISIBLE BY 16 A PADDING WILL BE ADDED TO THE PLAINTEXT. BUT IT WILL NOT BE REMOVED
    AES aes(AESKeyLength::AES_256);

    std::vector<unsigned char> plaintext = { 'H', 'e', 'l', 'l', 'o', ',', ' ', 'A', 'E', 'S', 'W', 'o','r','l','d','!',
    'H', 'e', 'l', 'l', 'o', ',', ' ', 'A', 'E', 'S', 'W', 'o','r','l' };

    std::vector<unsigned char> iv = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

    std::vector<unsigned char> key = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
                                       0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };
    std::vector<unsigned char> key_192 = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
        0xAA, 0xBB, 0xCC, 0xDD
    };
    std::vector<unsigned char> key_256 = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
        0xAA, 0xBB, 0xCC, 0xDD,
        0x11, 0x22, 0x33, 0x44,
        0x55, 0x66, 0x77, 0x88,
        0xFF, 0xEE, 0xDD, 0xCC
    };




    // Encrypt 
    std::vector<unsigned char> encryptedCBC = aes.EncryptCBC(plaintext, key_256, iv);
    std::vector<unsigned char> encryptedCFB = aes.EncryptCFB(plaintext, key_256, iv);
    std::vector<unsigned char> encryptedECB = aes.EncryptECB(plaintext, key_256);


    // Decrypt 
    std::vector<unsigned char> decryptedCBC = aes.DecryptCBC(encryptedCBC, key_256, iv);
    std::vector<unsigned char> decryptedCFB = aes.DecryptCFB(encryptedCFB, key_256, iv);
    std::vector<unsigned char> decryptedECB = aes.DecryptECB(encryptedECB, key_256);

    /*
    std::cout << "decryptedECB size = " << decryptedECB.size();
    std::cout << "\nvectortohex size = " << VectorToHex(plaintext).size();


    if (decryptedECB.size() != VectorToHex(plaintext).size())
    {
        removeElements(decryptedECB, decryptedECB.back()-1);
    }

    if (decryptedCBC.size() != VectorToHex(plaintext).size())
    {
        removeElements(decryptedCBC, decryptedCBC.back() - 1);
    }

    if (decryptedCFB.size() != VectorToHex(plaintext).size())
    {
        removeElements(decryptedCFB, decryptedCFB.back() - 1);
    }*/

    // Print the encrypted and decrypted messages
    std::cout << " encryption using CBC: \n";
    aes.printHexVector(encryptedCBC);
    std::cout << std::endl;
    aes.printHexVector(decryptedCBC);
    std::cout << std::endl;


    std::cout << " encryption using CFB: \n";
    aes.printHexVector(encryptedCFB);
    std::cout << std::endl;
    aes.printHexVector(decryptedCFB);
    std::cout << std::endl;


    std::cout << " encryption using ECB: \n";
    aes.printHexVector(encryptedECB);
    std::cout << std::endl;
    aes.printHexVector(decryptedECB);
    std::cout << std::endl;

    return 0;
}
