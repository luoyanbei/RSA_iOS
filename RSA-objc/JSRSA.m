//
//  JSRSA.m
//  RSA Example
//
//  Created by Js on 12/23/14.
//  Copyright (c) 2014 JS Lim. All rights reserved.
//

#include "js_rsa.h"
#import "JSRSA.h"

@implementation JSRSA

#pragma mark - helper
- (NSString *)publicKeyPath
{
    if (_publicKey == nil || [_publicKey isEqualToString:@""]) return nil;
    
    NSMutableArray *filenameChunks = [[_publicKey componentsSeparatedByString:@"."] mutableCopy];
    NSString *extension = filenameChunks[[filenameChunks count] - 1];
    [filenameChunks removeLastObject]; // remove the extension
    NSString *filename = [filenameChunks componentsJoinedByString:@"."]; // reconstruct the filename with no extension
        
    NSString *keyPath = [[NSBundle mainBundle] pathForResource:filename ofType:extension];
    NSLog(@"110--公钥路径=%@",keyPath);
    return keyPath;
}

- (NSString *)privateKeyPath
{
    if (_privateKey == nil || [_privateKey isEqualToString:@""]) return nil;
    
    NSMutableArray *filenameChunks = [[_privateKey componentsSeparatedByString:@"."] mutableCopy];
    NSString *extension = filenameChunks[[filenameChunks count] - 1];
    [filenameChunks removeLastObject]; // remove the extension
    NSString *filename = [filenameChunks componentsJoinedByString:@"."]; // reconstruct the filename with no extension
        
    NSString *keyPath = [[NSBundle mainBundle] pathForResource:filename ofType:extension];
    
    return keyPath;
}

#pragma mark - implementation
- (NSString *)publicEncrypt:(NSString *)plainText
{
    
    NSString *keyPath = [self publicKeyPath];
    if (keyPath == nil) return nil;
        
    char *cipherText = js_public_encrypt([plainText UTF8String], [keyPath UTF8String]);
    
    NSString *cipherTextString = [NSString stringWithUTF8String:cipherText];
    
    free(cipherText);
    
    return cipherTextString;
}

//新增--公钥加密
- (NSString *)publicEncrypt:(NSString *)plainText withPublicKey:(NSString *)pubKey andFileName:(NSString *)filename
{
    //在Document文件夹下创建私钥文件
    NSString * signedString = nil;
    NSString *documentPath = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) objectAtIndex:0];
    NSString *path = [documentPath stringByAppendingPathComponent:filename];
    
    // 把密钥写入文件
    NSString *formatKey = pubKey;
    //保存密钥，写入文件
    [formatKey writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:nil];
    
    //-----------------------------------------------
    NSString *keyPath = path;//[self publicKeyPath];
    if (keyPath == nil) return nil;
    
    char *cipherText = js_public_encrypt([plainText UTF8String], [keyPath UTF8String]);
    
    NSString *cipherTextString = [NSString stringWithUTF8String:cipherText];
    
    free(cipherText);
    
    //删除文件
    
    
    return cipherTextString;
}



- (NSString *)privateDecrypt:(NSString *)cipherText
{
    NSString *keyPath = [self privateKeyPath];
    if (keyPath == nil) return nil;
    
    char *plainText = js_private_decrypt([cipherText UTF8String], [keyPath UTF8String]);
    
    NSString *planTextString = [NSString stringWithUTF8String:plainText];
    
    free(plainText);
    
    return planTextString;
}

//新增--私钥解密
- (NSString *)privateDecrypt:(NSString *)cipherText withPublicKey:(NSString *)pubKey andFileName:(NSString *)filename
{
    //在Document文件夹下创建私钥文件
    NSString * signedString = nil;
    NSString *documentPath = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) objectAtIndex:0];
    NSString *path = [documentPath stringByAppendingPathComponent:filename];
    
    // 把密钥写入文件
    NSString *formatKey = pubKey;
    //保存密钥，写入文件
    [formatKey writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:nil];
    
    //-----------------------------------------------

    NSString *keyPath = path;//[self privateKeyPath];
    if (keyPath == nil) return nil;
    
    char *plainText = js_private_decrypt([cipherText UTF8String], [keyPath UTF8String]);
    
    NSString *planTextString = [NSString stringWithUTF8String:plainText];
    
    free(plainText);
    
    return planTextString;
}



- (NSString *)privateEncrypt:(NSString *)plainText
{
    NSString *keyPath = [self privateKeyPath];
    if (keyPath == nil) return nil;
        
    char *cipherText = js_private_encrypt([plainText UTF8String], [keyPath UTF8String]);
    
    NSString *cipherTextString = [NSString stringWithUTF8String:cipherText];
    
    free(cipherText);
    
    return cipherTextString;
}

- (NSString *)publicDecrypt:(NSString *)cipherText
{
    NSString *keyPath = [self publicKeyPath];
    if (keyPath == nil) return nil;
    
    char *plainText = js_public_decrypt([cipherText UTF8String], [keyPath UTF8String]);
    
    NSString *plainTextString = [NSString stringWithUTF8String:plainText];
    
    free(plainText);
    
    return plainTextString;
}

#pragma mark - instance method
+ (JSRSA *)sharedInstance
{
    static JSRSA *sharedInstance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        sharedInstance = [[[self class] alloc] init];
    });
    return sharedInstance;
}

@end
