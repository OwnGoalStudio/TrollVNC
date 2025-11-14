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

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface ZTSelfSignedCertificate : NSObject

/// PEM 格式的自签证书（-----BEGIN CERTIFICATE-----）
@property (nonatomic, readonly) NSString *certificatePEM;

/// PEM 格式的私钥（-----BEGIN RSA PRIVATE KEY-----）
@property (nonatomic, readonly) NSString *privateKeyPEM;

/// 生成一个 RSA 2048 自签证书 + 私钥，用 commonName 作为 CN。
/// 失败返回 nil。
+ (nullable instancetype)generateWithCommonName:(NSString *)commonName;

@end

NS_ASSUME_NONNULL_END
