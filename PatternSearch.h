#pragma once
#include <windows.h>

size_t wildcardCount = 0;

unsigned short* stringToHex(char* str, size_t strSize) {
    char* strArray;
    unsigned short* hexArray = (unsigned short*)malloc(((strSize / 3) * 2) + 2);
    size_t loopLen;

    if (*(str + 2) == 0x20) { //boslukluysa
        strArray = (char*)malloc(strSize);
        memcpy(strArray, str, strSize);
        loopLen = strSize / 3;
        for (size_t i = 0; i < loopLen; i++) {
            *(strArray + (3 * i) + 2) = 0x00;
        }
    }
    else { //bosluksuzsa
        size_t resizeStr = (strSize / 2) * 3;
        loopLen = resizeStr;
        strArray = (char*)malloc(resizeStr);
        for (size_t i = 0; i < strSize / 2; i++) { //0x20 leri 0x00 lama
            *(strArray + (3 * i)) = *(str + (1 * i));
            *(strArray + (3 * i) + 1) = *(str + (1 * i) + 1);
            *(strArray + (3 * i) + 2) = 0x00;
        }
    }

    char* byteStr;
    for (size_t i = 0; i < loopLen + 1; i++) {
        byteStr = (strArray + (3 * i));
        if (*byteStr == '?') {
            *(hexArray + i) = 0x3F3F;//??
            ++wildcardCount;
            continue;
        }
        *(hexArray + i) = static_cast<unsigned char>(strtol(byteStr, nullptr, 16));
    }

    free(strArray);

    return hexArray;
}

void* patternSearch(void* dst, size_t dstSize, char* patternStr, size_t maxPatternSize) {

    unsigned long long* patternAddresses = (unsigned long long*)malloc((maxPatternSize * 0x08) + 0x8); //patern adresleri sonda 0 olacak (bitirme qword)

    unsigned char* dstBase = (unsigned char*)dst;
    size_t patternLen = strlen(patternStr);
    size_t patternWordSize = patternLen / 3;
    size_t tempCounter = 0;

    unsigned short* pattern = stringToHex(patternStr, patternLen);
    unsigned char* cPattern = (unsigned char*)pattern;

    tempCounter = 0;
    size_t cIndexs = 0;
    size_t charCounter = 0;
    unsigned short* wildCardIndexes = (unsigned short*)malloc((wildcardCount + 1) * 2); //son karakter index'inide alacak
    unsigned char* wildPadding = (unsigned char*)malloc(wildcardCount + 1);

    for (size_t i = 0; i < patternWordSize; i++) {
        if (*(pattern + i) == 0x3F3F) {
            *(wildCardIndexes + tempCounter) = charCounter;
            *(wildPadding + tempCounter) = 0x01;
            for (size_t j = 1; j <= patternWordSize - i; j++) {
                if (*(pattern + i + j) != 0x3F3F) {
                    i += j;
                    *((unsigned char*)pattern + charCounter) = *(pattern + i);
                    ++charCounter;
                    break;
                }
                ++(*(wildPadding + tempCounter));
            }
            ++cIndexs;
            ++tempCounter;
        }
        else {
            *((unsigned char*)pattern + charCounter) = *(pattern + i);
            ++charCounter;
        }
    }
    *((unsigned char*)pattern + charCounter) = *(pattern + patternWordSize);
    *(wildCardIndexes + tempCounter) = charCounter;
    *(wildPadding + tempCounter) = 0x00;

    tempCounter = 0; //burdan sonrasý bu kullanýlan wild Index'i
    size_t memcmpSize = *wildCardIndexes;
    size_t success = 0;
    size_t foundOffsets = 0;
    unsigned char totalPadding = *(wildPadding);

    //pattern karsilastirma
    for (size_t offset = 0; offset < dstSize; ++offset) {
        if (memcmp(dstBase + offset, pattern, memcmpSize) == 0) {
            for (size_t j = 0; j < cIndexs; j++) {
                if (memcmp(dstBase + offset + memcmpSize + totalPadding,
                    (char*)pattern + memcmpSize,
                    *(wildCardIndexes + tempCounter + 1) - memcmpSize) == 0) {//- *(wildPadding + tempCounter + 1)) == 0) {
                    ++success;
                    ++tempCounter;
                    totalPadding += *(wildPadding + tempCounter);
                    memcmpSize = *(wildCardIndexes + tempCounter);
                    if (success == cIndexs) {
                        *(patternAddresses + foundOffsets) = (unsigned long long)dstBase + offset;
                        ++foundOffsets;
                    }
                }
                else {
                    tempCounter = 0;
                    success = 0;
                    memcmpSize = *(wildCardIndexes);
                    totalPadding = *(wildPadding);
                    break;
                }
            }
        }
    }
    *(patternAddresses + foundOffsets) = 0xCDCDCDCDCDCDCDCD;//0x0000000000000000;

    free(pattern);
    free(wildPadding);
    free(wildCardIndexes);

    return patternAddresses;
}