//
//  Encryption.h
//  Encryption
//
//  Created by coenen on 2019/8/2.
//  Copyright © 2019 侯克楠. All rights reserved.
//

#import <Foundation/Foundation.h>

typedef NS_ENUM(NSUInteger, EncryptionType) {
    EncryptionTypeMD5,
    EncryptionTypeSHA,
    EncryptionTypeSHA256,
    EncryptionTypeSHA512,
};
NS_ASSUME_NONNULL_BEGIN

@interface Encryption : NSObject
/**
 File encryptionType value under file path
 
 @param filePath The file path
 @param encryptionType The file encryptionType
 
 @return  encryptionType value
 */
+ (NSString *)encryptionOfFileAtPath:(NSString *)filePath FileEncryptionType:(EncryptionType) encryptionType;


@end

NS_ASSUME_NONNULL_END
