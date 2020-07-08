//
//  UAESCertificateManager.h
//  CSR证书请求
//
//  Created by lvzhao on 2020/7/8.
//  Copyright © 2020 吕. All rights reserved.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface UAESCertificateManager : NSObject
/**
 创建 UAESCertificateManager 对象
 */
+ (instancetype)sharedInstance;

/*
 生成CRS 公私钥
 **/
- (void)generateCSR;

@end

NS_ASSUME_NONNULL_END
