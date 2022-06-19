#include "../common/gdb_markers.h"
#include "bignum.h"
#include "enclave_t.h"
#include "ippcp.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <string>

#define PALIGN      __attribute__((aligned(4096)))
#define strlen_safe strlen

int printf(const char *fmt, ...) {
    return 0;
    char    buf[5000] = { '\0' };
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
    return 0;
}

int puts(const char *buf) {
    return 0;
    char buffer[1000];
    snprintf(buffer, sizeof(buffer), "%s\n", buf);
    ocall_print_string(buffer);
    return 0;
}

#define PRINT_EXAMPLE_STATUS(function_name, description, success_condition)       \
    printf("+--------------------------------------------------------------|\n"); \
    printf(" Function: %s\n", function_name);                                     \
    printf(" Description: %s\n", description);                                    \
    if ( success_condition ) {                                                    \
        printf(" Status: PASSED!\n");                                             \
    }                                                                             \
    else {                                                                        \
        printf(" Status: FAILED!\n");                                             \
    }                                                                             \
    printf("+--------------------------------------------------------------|\n");

static int checkStatus(const char *funcName, IppStatus expectedStatus, IppStatus status) {
    if ( expectedStatus != status ) {
        printf("%s: unexpected return status\n", funcName);
        printf("Expected: %s\n", ippcpGetStatusString(expectedStatus));
        printf("Received: %s\n", ippcpGetStatusString(status));
        return 0;
    }
    return 1;
}

static int bitSizeInBytes(int nBits) {
    return (nBits + 7) >> 3;
}

/*! Prime P factor */
static BigNumber P("0xEECFAE81B1B9B3C908810B10A1B5600199EB9F44AEF4FDA493B81A9E3D84F632"
                   "124EF0236E5D1E3B7E28FAE7AA040A2D5B252176459D1F397541BA2A58FB6599");

/*! Prime Q factor */
static BigNumber Q("0xC97FB1F027F453F6341233EAAAD1D9353F6C42D08866B1D05A0F2035028B9D86"
                   "9840B41666B42E92EA0DA3B43204B5CFCE3352524D0416A5A441E700AF461503");

/*! D mod (p-1) factor */
static BigNumber DP("0x54494CA63EBA0337E4E24023FCD69A5AEB07DDDC0183A4D0AC9B54B051F2B13E"
                    "D9490975EAB77414FF59C1F7692E9A2E202B38FC910A474174ADC93C1F67C981");

/*! D mod (q-1) factor */
static BigNumber DQ("0x471E0290FF0AF0750351B7F878864CA961ADBD3A8A7E991C5C0556A94C3146A7"
                    "F9803F8F6F8AE342E931FD8AE47A220D1B99A495849807FE39F9245A9836DA3D");

/*! Q^-1 mod p factor */
static BigNumber InvQ("0xB06C4FDABB6301198D265BDBAE9423B380F271F73453885093077FCD39E2119F"
                      "C98632154F5883B167A967BF402B4E9E2E0F9656E698EA3666EDFB25798039F7");

/*! Plain text */
static Ipp8u sourceMessageRef[] = "\xd4\x36\xe9\x95\x69\xfd\x32\xa7"
                                  "\xc8\xa0\x5b\xbc\x90\xd3\x2c\x49";

/*! Cipher text to decrypt. */
static Ipp8u cipherText[] = "\x12\x53\xE0\x4D\xC0\xA5\x39\x7B\xB4\x4A\x7A\xB8\x7E\x9B\xF2\xA0"
                            "\x39\xA3\x3D\x1E\x99\x6F\xC8\x2A\x94\xCC\xD3\x00\x74\xC9\x5D\xF7"
                            "\x63\x72\x20\x17\x06\x9E\x52\x68\xDA\x5D\x1C\x0B\x4F\x87\x2C\xF6"
                            "\x53\xC1\x1D\xF8\x23\x14\xA6\x79\x68\xDF\xEA\xE2\x8D\xEF\x04\xBB"
                            "\x6D\x84\xB1\xC3\x1D\x65\x4A\x19\x70\xE5\x78\x3B\xD6\xEB\x96\xA0"
                            "\x24\xC2\xCA\x2F\x4A\x90\xFE\x9F\x2E\xF5\xC9\xC1\x40\xE5\xBB\x48"
                            "\xDA\x95\x36\xAD\x87\x00\xC8\x4F\xC9\x13\x0A\xDE\xA7\x4E\x55\x8D"
                            "\x51\xA7\x4D\xDF\x85\xD8\xB5\x0D\xE9\x68\x38\xD6\x06\x3E\x09\x55";


void ecall_init() {
    mark_begin();
    printf("enclave init!\n");

    /* Internal function status */
    IppStatus status = ippStsNoErr;

    /* Size in bits of P factor */
    const int bitSizeP = P.BitSize();
    /* Size in bits of Q factor */
    const int bitSizeQ = Q.BitSize();

    /* Allocate memory for private key.
     * There are two types of private keys that are supported: Type1 and Type2.
     * You can choose any of them, depending on your private key representation.
     * This example uses Type2 key.
     * For more information, see
     * https://software.intel.com/en-us/ipp-crypto-reference-2019-rsa-getsizepublickey-rsa-getsizeprivatekeytype1-rsa-getsizeprivatekeytype2
     */
    int keySize = 0;
    ippsRSA_GetSizePrivateKeyType2(bitSizeP, bitSizeQ, &keySize);
    IppsRSAPrivateKeyState *pPrvKeyType2 = (IppsRSAPrivateKeyState *)(new Ipp8u[keySize]);
    ippsRSA_InitPrivateKeyType2(bitSizeP, bitSizeQ, pPrvKeyType2, keySize);

    /* Allocate memory for decrypted plain text, not less than RSA modulus size. */
    int    plainTextLen = bitSizeInBytes(bitSizeP + bitSizeQ);
    Ipp8u *pPlainText   = new Ipp8u[plainTextLen];

    do {
        /* Set private key */
        status = ippsRSA_SetPrivateKeyType2(P, Q, DP, DQ, InvQ, pPrvKeyType2);
        if ( !checkStatus("ippsRSA_SetPrivateKeyType2", ippStsNoErr, status) )
            break;

        /* Calculate temporary buffer size */
        int bufSize = 0;
        status      = ippsRSA_GetBufferSizePrivateKey(&bufSize, pPrvKeyType2);
        if ( !checkStatus("ippsRSA_GetBufferSizePrivateKey", ippStsNoErr, status) )
            break;

        /* Allocate memory for temporary buffer */
        Ipp8u *pScratchBuffer = new Ipp8u[bufSize];

        /* Decrypt message */
        status = ippsRSADecrypt_OAEP_rmf(
            cipherText, 0 /* optional label to be assotiated with the message */, 0, /* label length */
            pPlainText, &plainTextLen, pPrvKeyType2, ippsHashMethod_SHA1(), pScratchBuffer);

        if ( pScratchBuffer )
            delete[] pScratchBuffer;

        if ( !checkStatus("ippsRSADecrypt_OAEP_rmf", ippStsNoErr, status) )
            break;

        if ( 0 != memcmp(sourceMessageRef, pPlainText, sizeof(sourceMessageRef) - 1) ) {
            printf("ERROR: Decrypted and plain text messages do not match\n");
            status = ippStsErr;
        }
    } while ( 0 );
    mark_end();

    PRINT_EXAMPLE_STATUS("ippsRSADecrypt_OAEP_rmf", "RSA-OAEP 1024 (SHA1) Type2 decryption", ippStsNoErr == status)

    if ( pPlainText )
        delete[] pPlainText;
    if ( pPrvKeyType2 )
        delete[](Ipp8u *) pPrvKeyType2;
}

//////////////////////////////////////////////////////////////////////
//
// BigNumber
//
//////////////////////////////////////////////////////////////////////
BigNumber::~BigNumber() {
    delete[](Ipp8u *) m_pBN;
}

bool BigNumber::create(const Ipp32u *pData, int length, IppsBigNumSGN sgn) {
    int size;
    ippsBigNumGetSize(length, &size);
    m_pBN = (IppsBigNumState *)(new Ipp8u[size]);
    if ( !m_pBN )
        return false;
    ippsBigNumInit(length, m_pBN);
    if ( pData )
        ippsSet_BN(sgn, length, pData, m_pBN);
    return true;
}

//
// constructors
//
BigNumber::BigNumber(Ipp32u value) {
    create(&value, 1, IppsBigNumPOS);
}

BigNumber::BigNumber(Ipp32s value) {
    Ipp32s avalue = abs(value);
    create((Ipp32u *)&avalue, 1, (value < 0) ? IppsBigNumNEG : IppsBigNumPOS);
}

BigNumber::BigNumber(const IppsBigNumState *pBN) {
    IppsBigNumSGN bnSgn;
    int           bnBitLen;
    Ipp32u *      bnData;
    ippsRef_BN(&bnSgn, &bnBitLen, &bnData, pBN);

    create(bnData, BITSIZE_WORD(bnBitLen), bnSgn);
}

BigNumber::BigNumber(const Ipp32u *pData, int length, IppsBigNumSGN sgn) {
    create(pData, length, sgn);
}

static char HexDigitList[] = "0123456789ABCDEF";

BigNumber::BigNumber(const char *s) {
    bool neg = '-' == s[0];
    if ( neg )
        s++;
    bool hex = ('0' == s[0]) && (('x' == s[1]) || ('X' == s[1]));

    int    dataLen;
    Ipp32u base;
    if ( hex ) {
        s += 2;
        base    = 0x10;
        dataLen = (int)(strlen_safe(s) + 7) / 8;
    }
    else {
        base    = 10;
        dataLen = (int)(strlen_safe(s) + 9) / 10;
    }

    create(0, dataLen);
    *(this) = Zero();
    while ( *s ) {
        char   tmp[2] = { s[0], 0 };
        Ipp32u digit  = (Ipp32u)strcspn(HexDigitList, tmp);
        *this         = (*this) * base + BigNumber(digit);
        s++;
    }

    if ( neg )
        (*this) = Zero() - (*this);
}

BigNumber::BigNumber(const BigNumber &bn) {
    IppsBigNumSGN bnSgn;
    int           bnBitLen;
    Ipp32u *      bnData;
    ippsRef_BN(&bnSgn, &bnBitLen, &bnData, bn);

    create(bnData, BITSIZE_WORD(bnBitLen), bnSgn);
}

//
// set value
//
void BigNumber::Set(const Ipp32u *pData, int length, IppsBigNumSGN sgn) {
    ippsSet_BN(sgn, length, pData, BN(*this));
}

//
// constants
//
const BigNumber &BigNumber::Zero() {
    static const BigNumber zero(0);
    return zero;
}

const BigNumber &BigNumber::One() {
    static const BigNumber one(1);
    return one;
}

const BigNumber &BigNumber::Two() {
    static const BigNumber two(2);
    return two;
}

//
// arithmetic operators
//
BigNumber &BigNumber::operator=(const BigNumber &bn) {
    if ( this != &bn ) { // prevent self copy
        IppsBigNumSGN bnSgn;
        int           bnBitLen;
        Ipp32u *      bnData;
        ippsRef_BN(&bnSgn, &bnBitLen, &bnData, bn);

        delete[](Ipp8u *) m_pBN;
        create(bnData, BITSIZE_WORD(bnBitLen), bnSgn);
    }
    return *this;
}

BigNumber &BigNumber::operator+=(const BigNumber &bn) {
    int aBitLen;
    ippsRef_BN(NULL, &aBitLen, NULL, *this);
    int bBitLen;
    ippsRef_BN(NULL, &bBitLen, NULL, bn);
    int rBitLen = IPP_MAX(aBitLen, bBitLen) + 1;

    BigNumber result(0, BITSIZE_WORD(rBitLen));
    ippsAdd_BN(*this, bn, result);
    *this = result;
    return *this;
}

BigNumber &BigNumber::operator-=(const BigNumber &bn) {
    int aBitLen;
    ippsRef_BN(NULL, &aBitLen, NULL, *this);
    int bBitLen;
    ippsRef_BN(NULL, &bBitLen, NULL, bn);
    int rBitLen = IPP_MAX(aBitLen, bBitLen);

    BigNumber result(0, BITSIZE_WORD(rBitLen));
    ippsSub_BN(*this, bn, result);
    *this = result;
    return *this;
}

BigNumber &BigNumber::operator*=(const BigNumber &bn) {
    int aBitLen;
    ippsRef_BN(NULL, &aBitLen, NULL, *this);
    int bBitLen;
    ippsRef_BN(NULL, &bBitLen, NULL, bn);
    int rBitLen = aBitLen + bBitLen;

    BigNumber result(0, BITSIZE_WORD(rBitLen));
    ippsMul_BN(*this, bn, result);
    *this = result;
    return *this;
}

BigNumber &BigNumber::operator*=(Ipp32u n) {
    int aBitLen;
    ippsRef_BN(NULL, &aBitLen, NULL, *this);

    BigNumber result(0, BITSIZE_WORD(aBitLen + 32));
    BigNumber bn(n);
    ippsMul_BN(*this, bn, result);
    *this = result;
    return *this;
}

BigNumber &BigNumber::operator%=(const BigNumber &bn) {
    BigNumber remainder(bn);
    ippsMod_BN(BN(*this), BN(bn), BN(remainder));
    *this = remainder;
    return *this;
}

BigNumber &BigNumber::operator/=(const BigNumber &bn) {
    BigNumber quotient(*this);
    BigNumber remainder(bn);
    ippsDiv_BN(BN(*this), BN(bn), BN(quotient), BN(remainder));
    *this = quotient;
    return *this;
}

BigNumber operator+(const BigNumber &a, const BigNumber &b) {
    BigNumber r(a);
    return r += b;
}

BigNumber operator-(const BigNumber &a, const BigNumber &b) {
    BigNumber r(a);
    return r -= b;
}

BigNumber operator*(const BigNumber &a, const BigNumber &b) {
    BigNumber r(a);
    return r *= b;
}

BigNumber operator*(const BigNumber &a, Ipp32u n) {
    BigNumber r(a);
    return r *= n;
}

BigNumber operator/(const BigNumber &a, const BigNumber &b) {
    BigNumber q(a);
    return q /= b;
}

BigNumber operator%(const BigNumber &a, const BigNumber &b) {
    BigNumber r(b);
    ippsMod_BN(BN(a), BN(b), BN(r));
    return r;
}

//
// modulo arithmetic
//
BigNumber BigNumber::Modulo(const BigNumber &a) const {
    return a % *this;
}

BigNumber BigNumber::InverseAdd(const BigNumber &a) const {
    BigNumber t = Modulo(a);
    if ( t == BigNumber::Zero() )
        return t;
    else
        return *this - t;
}

BigNumber BigNumber::InverseMul(const BigNumber &a) const {
    BigNumber r(*this);
    ippsModInv_BN(BN(a), BN(*this), BN(r));
    return r;
}

BigNumber BigNumber::ModAdd(const BigNumber &a, const BigNumber &b) const {
    BigNumber r = this->Modulo(a + b);
    return r;
}

BigNumber BigNumber::ModSub(const BigNumber &a, const BigNumber &b) const {
    BigNumber r = this->Modulo(a + this->InverseAdd(b));
    return r;
}

BigNumber BigNumber::ModMul(const BigNumber &a, const BigNumber &b) const {
    BigNumber r = this->Modulo(a * b);
    return r;
}

//
// comparison
//
int BigNumber::compare(const BigNumber &bn) const {
    Ipp32u    result;
    BigNumber tmp = *this - bn;
    ippsCmpZero_BN(BN(tmp), &result);
    return (result == IS_ZERO) ? 0 : (result == GREATER_THAN_ZERO) ? 1 : -1;
}

bool operator<(const BigNumber &a, const BigNumber &b) {
    return a.compare(b) < 0;
}
bool operator>(const BigNumber &a, const BigNumber &b) {
    return a.compare(b) > 0;
}
bool operator==(const BigNumber &a, const BigNumber &b) {
    return 0 == a.compare(b);
}
bool operator!=(const BigNumber &a, const BigNumber &b) {
    return 0 != a.compare(b);
}

// easy tests
//
bool BigNumber::IsOdd() const {
    Ipp32u *bnData;
    ippsRef_BN(NULL, NULL, &bnData, *this);
    return bnData[0] & 1;
}

//
// size of BigNumber
//
int BigNumber::LSB() const {
    if ( *this == BigNumber::Zero() )
        return 0;

    vector<Ipp32u> v;
    num2vec(v);

    int                      lsb = 0;
    vector<Ipp32u>::iterator i;
    for ( i = v.begin(); i != v.end(); i++ ) {
        Ipp32u x = *i;
        if ( 0 == x )
            lsb += 32;
        else {
            while ( 0 == (x & 1) ) {
                lsb++;
                x >>= 1;
            }
            break;
        }
    }
    return lsb;
}

int BigNumber::MSB() const {
    if ( *this == BigNumber::Zero() )
        return 0;

    vector<Ipp32u> v;
    num2vec(v);

    int                              msb = (int)v.size() * 32 - 1;
    vector<Ipp32u>::reverse_iterator i;
    for ( i = v.rbegin(); i != v.rend(); i++ ) {
        Ipp32u x = *i;
        if ( 0 == x )
            msb -= 32;
        else {
            while ( !(x & 0x80000000) ) {
                msb--;
                x <<= 1;
            }
            break;
        }
    }
    return msb;
}

int Bit(const vector<Ipp32u> &v, int n) {
    return 0 != (v[n >> 5] & (1 << (n & 0x1F)));
}

//
// conversions and output
//
void BigNumber::num2vec(vector<Ipp32u> &v) const {
    int     bnBitLen;
    Ipp32u *bnData;
    ippsRef_BN(NULL, &bnBitLen, &bnData, *this);

    int len = BITSIZE_WORD(bnBitLen);
    ;
    for ( int n = 0; n < len; n++ )
        v.push_back(bnData[n]);
}

void BigNumber::num2hex(string &s) const {
    IppsBigNumSGN bnSgn;
    int           bnBitLen;
    Ipp32u *      bnData;
    ippsRef_BN(&bnSgn, &bnBitLen, &bnData, *this);

    int len = BITSIZE_WORD(bnBitLen);

    s.append(1, (bnSgn == ippBigNumNEG) ? '-' : ' ');
    s.append(1, '0');
    s.append(1, 'x');
    for ( int n = len; n > 0; n-- ) {
        Ipp32u x = bnData[n - 1];
        for ( int nd = 8; nd > 0; nd-- ) {
            char c = HexDigitList[(x >> (nd - 1) * 4) & 0xF];
            s.append(1, c);
        }
    }
}
