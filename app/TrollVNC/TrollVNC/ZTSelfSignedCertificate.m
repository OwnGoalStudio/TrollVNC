/*
 This file is part of TrollVNC
 Copyright (c) 2025 82Flex <82flex@gmail.com> and contributors

 This program is free software; you can redistribute it and/or modify
 it under the terms of the GNU General Public License version 2
 as published by the Free Software Foundation.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program. If not, see <https://www.gnu.org/licenses/>.
*/

#import "ZTSelfSignedCertificate.h"
#import <Security/Security.h>

#pragma mark - 私有 Security 符号

extern SecCertificateRef SecGenerateSelfSignedCertificate(
    CFArrayRef subject,
    CFDictionaryRef __nullable parameters,
    SecKeyRef publicKey,
    SecKeyRef privateKey
);

extern const CFStringRef kSecOidCommonName;
extern const CFStringRef kSecOidOrganization;
extern const CFStringRef kSecCSRBasicContraintsPathLen;
extern const CFStringRef kSecCertificateKeyUsage;

enum {
    kSecKeyUsageUnspecified        = 0,
    kSecKeyUsageDigitalSignature   = 1 << 0,
    kSecKeyUsageNonRepudiation     = 1 << 1,
    kSecKeyUsageKeyEncipherment    = 1 << 2,
    kSecKeyUsageDataEncipherment   = 1 << 3,
    kSecKeyUsageKeyAgreement       = 1 << 4,
    kSecKeyUsageKeyCertSign        = 1 << 5,
    kSecKeyUsageCRLSign            = 1 << 6,
    kSecKeyUsageEncipherOnly       = 1 << 7,
    kSecKeyUsageDecipherOnly       = 1 << 8,
    kSecKeyUsageAll                = 0x7FF
};


#pragma mark - DER -> PEM
static NSString *ZTPEMFromDER(NSData *der,
                              NSString *header,
                              NSString *footer)
{
    if (!der) return nil;

    NSString *b64 = [der base64EncodedStringWithOptions:0];
    NSMutableString *pem = [NSMutableString string];

    [pem appendFormat:@"-----BEGIN %@-----\n", header];

    for (NSUInteger i = 0; i < b64.length; i += 64) {
        NSUInteger len = MIN(64, b64.length - i);
        [pem appendFormat:@"%@\n", [b64 substringWithRange:NSMakeRange(i, len)]];
    }

    [pem appendFormat:@"-----END %@-----\n", footer];
    return pem;
}


#pragma mark - 实现

@interface ZTSelfSignedCertificate ()
@property (nonatomic, readwrite) NSString *certificatePEM;
@property (nonatomic, readwrite) NSString *privateKeyPEM;
@end


@implementation ZTSelfSignedCertificate

+ (instancetype)generateWithCommonName:(NSString *)commonName
{
    ZTSelfSignedCertificate *obj = [[self alloc] init];
    if (![obj _generateWithCommonName:commonName]) {
        return nil;
    }
    return obj;
}


- (BOOL)_generateWithCommonName:(NSString *)commonName
{
    OSStatus status = errSecSuccess;
    SecKeyRef publicKey = NULL;
    SecKeyRef privateKey = NULL;
    SecCertificateRef cert = NULL;

    CFStringRef cfCommonName = (__bridge CFStringRef)commonName;


    // 1. 生成 RSA key pair
    {
        CFMutableDictionaryRef keyParams =
        CFDictionaryCreateMutable(kCFAllocatorDefault,
                                  0,
                                  &kCFTypeDictionaryKeyCallBacks,
                                  &kCFTypeDictionaryValueCallBacks);

        if (!keyParams) goto cleanup;

        CFDictionaryAddValue(keyParams, kSecAttrKeyType, kSecAttrKeyTypeRSA);
        CFDictionaryAddValue(keyParams, kSecAttrKeySizeInBits, CFSTR("2048"));
        CFDictionaryAddValue(keyParams, kSecAttrLabel, cfCommonName);

        status = SecKeyGeneratePair(keyParams, &publicKey, &privateKey);
        CFRelease(keyParams);

        if (status != errSecSuccess || !publicKey || !privateKey) goto cleanup;
    }


    // 2. certParams（无 SAN 版本，避免 CSR encode 报错）
    CFDictionaryRef certParams = NULL;
    {
        CFIndex usageInt = kSecKeyUsageAll;
        CFNumberRef usage =
        CFNumberCreate(kCFAllocatorDefault, kCFNumberCFIndexType, &usageInt);

        CFIndex lenInt = 0;
        CFNumberRef len =
        CFNumberCreate(kCFAllocatorDefault, kCFNumberCFIndexType, &lenInt);

        CFTypeRef keys[]   = { kSecCSRBasicContraintsPathLen, kSecCertificateKeyUsage };
        CFTypeRef values[] = { len, usage };

        certParams =
        CFDictionaryCreate(kCFAllocatorDefault,
                           keys,
                           values,
                           2,
                           &kCFTypeDictionaryKeyCallBacks,
                           &kCFTypeDictionaryValueCallBacks);

        CFRelease(len);
        CFRelease(usage);

        if (!certParams) goto cleanup;
    }


    // 3. subject（三层 CFArray，必须精确模仿 CUPS）

    CFArrayRef subject = NULL;
    CFArrayRef oPair = NULL;
    CFArrayRef cnPair = NULL;
    CFArrayRef oRDN = NULL;
    CFArrayRef cnRDN = NULL;

    {
        const void *oFields[2] = { kSecOidOrganization, CFSTR("") };
        oPair = CFArrayCreate(kCFAllocatorDefault, oFields, 2, &kCFTypeArrayCallBacks);

        const void *cnFields[2] = { kSecOidCommonName, cfCommonName };
        cnPair = CFArrayCreate(kCFAllocatorDefault, cnFields, 2, &kCFTypeArrayCallBacks);

        // 2nd 层（每个 RDN 是“数组包一个数组”）
        const void *oRDNFields[1] = { oPair };
        oRDN = CFArrayCreate(kCFAllocatorDefault, oRDNFields, 1, &kCFTypeArrayCallBacks);

        const void *cnRDNFields[1] = { cnPair };
        cnRDN = CFArrayCreate(kCFAllocatorDefault, cnRDNFields, 1, &kCFTypeArrayCallBacks);

        // 顶层 subject（数组包多个 RDN）
        const void *rdnList[2] = { oRDN, cnRDN };
        subject = CFArrayCreate(kCFAllocatorDefault, rdnList, 2, &kCFTypeArrayCallBacks);

        if (!subject) goto cleanup;
    }


    // 4. Self-signed cert
    cert = SecGenerateSelfSignedCertificate(subject, certParams, publicKey, privateKey);

    // subject 相关全部释放（Security 内部已 retain）
    CFRelease(subject);
    CFRelease(oRDN);
    CFRelease(cnRDN);
    CFRelease(oPair);
    CFRelease(cnPair);

    CFRelease(certParams);

    if (!cert) goto cleanup;


    // 5. 导出 certificate (PEM)
    {
        CFDataRef certData = SecCertificateCopyData(cert);
        if (!certData) goto cleanup;

        NSData *der = (__bridge_transfer NSData *)certData;

        NSString *pem = ZTPEMFromDER(der, @"CERTIFICATE", @"CERTIFICATE");
        if (!pem) goto cleanup;

        self.certificatePEM = pem;
    }


    // 6. 导出 private key (PEM)
    {
        CFErrorRef error = NULL;
        CFDataRef keyData = SecKeyCopyExternalRepresentation(privateKey, &error);
        if (!keyData) {
            if (error) CFRelease(error);
            goto cleanup;
        }

        NSData *der = (__bridge_transfer NSData *)keyData;

        NSString *pem =
        ZTPEMFromDER(der, @"RSA PRIVATE KEY", @"RSA PRIVATE KEY");
        if (!pem) goto cleanup;

        self.privateKeyPEM = pem;
    }


cleanup:
    if (cert) CFRelease(cert);
    if (publicKey) CFRelease(publicKey);
    if (privateKey) CFRelease(privateKey);

    return (self.certificatePEM && self.privateKeyPEM);
}

@end
