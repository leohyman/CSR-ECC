//
//  ViewController.m
//  CSR证书请求
//
//  Created by 刘成利 on 2017/6/21.
//  Copyright © 2017年 刘成利. All rights reserved.
//

#import "ViewController.h"
#import "UAESCertificateManager.h"
@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    
    [[UAESCertificateManager sharedInstance] generateCSR];
    
}



- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}


@end
