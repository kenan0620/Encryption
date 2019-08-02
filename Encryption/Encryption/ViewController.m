//
//  ViewController.m
//  Encryption
//
//  Created by coenen on 2019/8/2.
//  Copyright © 2019 侯克楠. All rights reserved.
//



#import "ViewController.h"

#import "CocoaSecurity.h"

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view.
    NSString *df = @"additional";

    CocoaSecurityResult *result =   [CocoaSecurity md5:df];
    NSLog(@"result %@",result.hex);
    NSLog(@"result %@",result.hexLower);
    CocoaSecurityResult *result1 =   [CocoaSecurity sha512:df];
    NSLog(@"result %@",result1.hex);
    NSLog(@"result %@",result1.hexLower);
}

- (void)descriptionEncryption{
    /**
     https://docs.microsoft.com/zh-cn/dotnet/api/system.security.cryptography.hashalgorithmname?redirectedfrom=MSDN&view=netframework-4.8
     HashAlgorithmName(String)
     MD5 获取表示“MD5”的哈希算法名称。
     Name 获取算法名称的基础字符串表示形式。
     SHA1 获取表示“SHA1”的哈希算法名称。
     SHA256 获取表示“SHA256”的哈希算法名称。
     SHA384 获取表示“SHA384”的哈希算法名称。
     SHA512 获取表示“SHA512”的哈希算法名称。
     */
}

@end
