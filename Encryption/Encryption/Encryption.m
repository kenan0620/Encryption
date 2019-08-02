//
//  Encryption.m
//  Encryption
//
//  Created by coenen on 2019/8/2.
//  Copyright © 2019 侯克楠. All rights reserved.
//

#import "Encryption.h"

#include <CommonCrypto/CommonDigest.h>
#include <CoreFoundation/CoreFoundation.h>
#include <stdint.h>
#include <stdio.h>

// Constants
static const size_t FileHashDefaultChunkSizeForReadingData = 4096;

// Function pointer types for functions used in the computation
// of a cryptographic hash.
typedef int (*FileHashInitFunction) (uint8_t *hashObjectPointer[]);
typedef int (*FileHashUpdateFunction) (uint8_t *hashObjectPointer[], const void *data, CC_LONG len);
typedef int (*FileHashFinalFunction) (unsigned char *md, uint8_t *hashObjectPointer[]);

// Structure used to describe a hash computation context.
typedef struct _FileHashComputationContext {
    FileHashInitFunction initFunction;
    FileHashUpdateFunction updateFunction;
    FileHashFinalFunction finalFunction;
    size_t digestLength;
    uint8_t **hashObjectPointer;
} FileHashComputationContext;

#define FileHashComputationContextInitialize(context, hashAlgorithmName)                    \
CC_##hashAlgorithmName##_CTX hashObjectFor##hashAlgorithmName;                          \
context.initFunction      = (FileHashInitFunction)&CC_##hashAlgorithmName##_Init;       \
context.updateFunction    = (FileHashUpdateFunction)&CC_##hashAlgorithmName##_Update;   \
context.finalFunction     = (FileHashFinalFunction)&CC_##hashAlgorithmName##_Final;     \
context.digestLength      = CC_##hashAlgorithmName##_DIGEST_LENGTH;                     \
context.hashObjectPointer = (uint8_t **)&hashObjectFor##hashAlgorithmName

@implementation Encryption

+ (NSString *)hashOfFileAtPath:(NSString *)filePath withComputationContext:(FileHashComputationContext *)context {
    NSString *result = nil;
    if (!filePath) {
        return @"";
    }
    CFURLRef fileURL = CFURLCreateWithFileSystemPath(kCFAllocatorDefault, (CFStringRef)filePath, kCFURLPOSIXPathStyle, (Boolean)false);
    CFReadStreamRef readStream = fileURL ? CFReadStreamCreateWithFile(kCFAllocatorDefault, fileURL) : NULL;
    BOOL didSucceed = readStream ? (BOOL)CFReadStreamOpen(readStream) : NO;
    if (didSucceed) {
        
        // Use default value for the chunk size for reading data.
        const size_t chunkSizeForReadingData = FileHashDefaultChunkSizeForReadingData;
        
        // Initialize the hash object
        (*context->initFunction)(context->hashObjectPointer);
        
        // Feed the data to the hash object.
        BOOL hasMoreData = YES;
        while (hasMoreData) {
            uint8_t buffer[chunkSizeForReadingData];
            CFIndex readBytesCount = CFReadStreamRead(readStream, (UInt8 *)buffer, (CFIndex)sizeof(buffer));
            if (readBytesCount == -1) {
                break;
            } else if (readBytesCount == 0) {
                hasMoreData = NO;
            } else {
                (*context->updateFunction)(context->hashObjectPointer, (const void *)buffer, (CC_LONG)readBytesCount);
            }
        }
        
        // Compute the hash digest
        unsigned char digest[context->digestLength];
        (*context->finalFunction)(digest, context->hashObjectPointer);
        
        // Close the read stream.
        CFReadStreamClose(readStream);
        
        // Proceed if the read operation succeeded.
        didSucceed = !hasMoreData;
        if (didSucceed) {
            char hash[2 * sizeof(digest) + 1];
            for (size_t i = 0; i < sizeof(digest); ++i) {
                snprintf(hash + (2 * i), 3, "%02X", (int)(digest[i]));
            }
            result = [NSString stringWithUTF8String:hash];
        }
    }
    if (readStream) CFRelease(readStream);
    if (fileURL)    CFRelease(fileURL);
    return result;
}

+ (NSString *)encryptionOfFileAtPath:(NSString *)filePath FileEncryptionType:(EncryptionType) encryptionType{
    FileHashComputationContext context;
    switch (encryptionType) {
        case EncryptionTypeMD5:{
            FileHashComputationContextInitialize(context, MD5);

        }
            break;
        case EncryptionTypeSHA:{
            FileHashComputationContextInitialize(context, SHA1);
            
        }
            break;
        case EncryptionTypeSHA256:{
            FileHashComputationContextInitialize(context, SHA256);
            
        }
            break;
        case EncryptionTypeSHA512:{
            FileHashComputationContextInitialize(context, SHA512);
            
        }
            break;
    }
    return [self hashOfFileAtPath:filePath withComputationContext:&context];
}
@end
