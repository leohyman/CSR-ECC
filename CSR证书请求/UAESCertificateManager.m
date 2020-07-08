//
//  UAESCertificateManager.m
//  CSR证书请求
//
//  Created by lvzhao on 2020/7/8.
//  Copyright © 2020 吕. All rights reserved.
//

#import "UAESCertificateManager.h"
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <string.h>



@implementation UAESCertificateManager
static UAESCertificateManager* sharedInstance = nil;
+ (UAESCertificateManager*)sharedInstance{
    // lazy instantiation
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        sharedInstance = [[UAESCertificateManager alloc] init];
    });
    return sharedInstance;
}

- (id)init{
    self = [super init];
    if (self) {

    }
    return self;
}

/*
 生成CRS 公私钥
 **/
- (void)generateCSR{
    
    NSLog(@"开始创建");
    /* 生成pkcs10 证书请求  格式：/CN=参数1/O=参数2/OU=参数3……
       * 例如："/CN=www.cicc.com/O=cicc.com/OU=IT/ST=Beijing City/L=beijing/C=CN/emailAddress=934800996@qq.com"
       * CN: 通用名称，域名  Common Name
       * O:  组织          Organization
       * OU: 部门          Organizational Unit
       * ST: 省份          State
       * L:  城市          Locality
       * C:  国家          Country
       */
    
    NSString *info =@"/CN=www.34456.com/O=ABC/OU=DE/ST=ShangHai City/L=shanghai/C=CN/emailAddress=abc@year.com";
    char chDN[255];
    char chCSR[2048] = {0};
    char privateKey[2048] = {0};

    memcpy(chDN, [info cStringUsingEncoding:NSASCIIStringEncoding], 2*[info length]);
    GenCSR(chDN, (int)chDN, chCSR, sizeof(chCSR),privateKey);
    NSString* pkcs10=[NSString stringWithFormat:@"%s",chCSR];
    NSString* priKey=[NSString stringWithFormat:@"%s",privateKey];
    // 返回的数组的第一个为PKCS10 CSR证书请求，第二个值为（未加密的）私钥
    NSLog(@"创建成功:\n %@ \n PrivateKey:\n%@ \n",pkcs10,priKey);
    
}


#pragma mark -- OpenSSL
/*
 * subject is expected to be in the format /type0=value0/type1=value1/type2=...
 * where characters may be escaped by \
 */
X509_NAME *parse_name(char *subject, long chtype, int multirdn)
{
    size_t buflen = strlen(subject)+1; /* to copy the types and values into. due to escaping, the copy can only become shorter */
    char *buf = OPENSSL_malloc(buflen);
    size_t max_ne = buflen / 2 + 1; /* maximum number of name elements */
    char **ne_types = OPENSSL_malloc(max_ne * sizeof (char *));
    char **ne_values = OPENSSL_malloc(max_ne * sizeof (char *));
    int *mval = OPENSSL_malloc (max_ne * sizeof (int));
    
    char *sp = subject, *bp = buf;
    int i, ne_num = 0;
    
    X509_NAME *n = NULL;
    int nid;
    
    if (!buf || !ne_types || !ne_values || !mval)
    {
        //BIO_printf(bio_err, "malloc error\n");
        goto error;
    }
    
    if (*subject != '/')
    {
        //BIO_printf(bio_err, "Subject does not start with '/'.\n");
        goto error;
    }
    sp++; /* skip leading / */
    
    /* no multivalued RDN by default */
    mval[ne_num] = 0;
    
    while (*sp)
    {
        /* collect type */
        ne_types[ne_num] = bp;
        while (*sp)
        {
            if (*sp == '\\') /* is there anything to escape in the type...? */
            {
                if (*++sp)
                    *bp++ = *sp++;
                else
                {
                    //BIO_printf(bio_err, "escape character at end of string\n");
                    goto error;
                }
            }
            else if (*sp == '=')
            {
                sp++;
                *bp++ = '\0';
                break;
            }
            else
                *bp++ = *sp++;
        }
        if (!*sp)
        {
            //BIO_printf(bio_err, "end of string encountered while processing type of subject name element #%d\n", ne_num);
            goto error;
        }
        ne_values[ne_num] = bp;
        while (*sp)
        {
            if (*sp == '\\')
            {
                if (*++sp)
                    *bp++ = *sp++;
                else
                {
                    //BIO_printf(bio_err, "escape character at end of string\n");
                    goto error;
                }
            }
            else if (*sp == '/')
            {
                sp++;
                /* no multivalued RDN by default */
                mval[ne_num+1] = 0;
                break;
            }
            else if (*sp == '+' && multirdn)
            {
                /* a not escaped + signals a mutlivalued RDN */
                sp++;
                mval[ne_num+1] = -1;
                break;
            }
            else
                *bp++ = *sp++;
        }
        *bp++ = '\0';
        ne_num++;
    }
    
    if (!(n = X509_NAME_new()))
        goto error;
    
    for (i = 0; i < ne_num; i++)
    {
        if ((nid=OBJ_txt2nid(ne_types[i])) == NID_undef)
        {
            //BIO_printf(bio_err, "Subject Attribute %s has no known NID, skipped\n", ne_types[i]);
            continue;
        }
        
        if (!*ne_values[i])
        {
            //BIO_printf(bio_err, "No value provided for Subject Attribute %s, skipped\n", ne_types[i]);
            continue;
        }
        
        if (!X509_NAME_add_entry_by_NID(n, nid, chtype, (unsigned char*)ne_values[i], -1,-1,mval[i]))
            goto error;
    }
    
    OPENSSL_free(ne_values);
    OPENSSL_free(ne_types);
    OPENSSL_free(buf);
    OPENSSL_free(mval);
    return n;
    
error:
    X509_NAME_free(n);
    if (ne_values)
        OPENSSL_free(ne_values);
    if (ne_types)
        OPENSSL_free(ne_types);
    if (mval)
        OPENSSL_free(mval);
    if (buf)
        OPENSSL_free(buf);
    return NULL;
}



long int GenCSR(char *pbDN, int nDNLen, char *pCSR, size_t nCSRSize, char *privateKey)
{
    X509_REQ        *pX509Req = NULL;
    int             iRV = 0;
    long            lVer = 3;
    X509_NAME       *pX509DN = NULL;
    EVP_PKEY        *pEVPKey = NULL;
    char            szBuf[255] = {0};
    unsigned char   mdout[20];
    unsigned int    nModLen;
    const EVP_MD    *md = NULL;
    BIO             *pPemBIO = NULL;
    BUF_MEM         *pBMem = NULL;
    
    //STACK_OF(X509_EXTENSION) *pX509Ext;
    
    if(pbDN == NULL)
    {
        return -1;
    }
    
    // 用户信息
    pX509DN = parse_name(pbDN, V_ASN1_UTF8STRING, 0);
    // 创建请求对象
    pX509Req = X509_REQ_new();
    // 设置版本号
    iRV = X509_REQ_set_version(pX509Req, lVer);
    
    // 用户信息放入 subject pX509Name
    iRV = X509_REQ_set_subject_name(pX509Req, pX509DN);
    
    
    
    
    pEVPKey = EVP_PKEY_new();
    
    //1首先声明 EC_KEY *ec_key; 结构，椭圆曲线的参数;私钥和公 钥都保存在这个结构中。
    EC_KEY *ec_key;
    //2声明 EC_GROUP *ec_group; 结构，这个结构保存着椭圆曲线 的参数。
    EC_GROUP *ec_group;
    //3使用 ec_key = EC_KEY_new(); 生成一个新的 EC_KEY 结构。
    ec_key = EC_KEY_new();
    
    //选择一条曲线参数，填充 EC_GROUP 结构:ec_group = EC_GROUP_new_by_curve_name(NID_secp256k1); NID_secp256k1 为椭圆曲线，
    ec_group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    
    EC_KEY_set_asn1_flag(ec_key,OPENSSL_EC_NAMED_CURVE);
    EC_GROUP_set_asn1_flag(ec_group,OPENSSL_EC_NAMED_CURVE);
    
    //将 EC_GROUP 结 构的内容填充到 EC_KEY 结构中。
    EC_KEY_set_group(ec_key, ec_group);
    //生成私钥和 公钥 对，并填充到 EC_KEY 结构中。
    EC_KEY_generate_key(ec_key);
    
    

     //将ec_key赋给EVP_PKEY结构
    EVP_PKEY_assign_EC_KEY(pEVPKey, ec_key);
    
    // 加入主体公钥pEVPKey到证书请求
    iRV = X509_REQ_set_pubkey(pX509Req, pEVPKey);
    // 用主体结构私钥对上面的req进行签名
    // 签名方式为哈希（非MD5）
    md  = EVP_sha256();
    // 计算消息摘要: mdout为结果，nModLen为结果的长度 (摘要不可逆推原文)
    iRV = X509_REQ_digest(pX509Req, md, mdout, &nModLen);
    
    // 用私钥对摘要签名
    iRV = X509_REQ_sign(pX509Req, pEVPKey, md);
    if(!iRV)
    {
        printf("sign err!\n");
        X509_REQ_free(pX509Req);
        return -1;
    }
    
    // 2.1  返回PEM字符  PKCS10证书请求
    pPemBIO = BIO_new(BIO_s_mem());
    PEM_write_bio_X509_REQ(pPemBIO, pX509Req);
    BIO_get_mem_ptr(pPemBIO,&pBMem);
    if(pBMem->length <= nCSRSize)
    {
        memcpy(pCSR, pBMem->data, pBMem->length);
    }
    BIO_free(pPemBIO);
    

    // 2.2 获取公钥 PEM_read_bio_PUBKEY   PEM_read_bio_RSA_PUBKEY PEM_write_bio_RSAPublicKey
    char publicKey[1024] = {0};
    pPemBIO = BIO_new(BIO_s_mem());
    if (PEM_write_bio_EC_PUBKEY(pPemBIO, ec_key)!=1){
        printf("pulic key error\n");
    }


    // 公钥转换输出
    BIO_get_mem_ptr(pPemBIO,&pBMem);
    if(pBMem->length <= nCSRSize)
    {
        memcpy(publicKey, pBMem->data, pBMem->length);
    }
    
    BIO_free(pPemBIO);
        
    // 2.3 获取私钥
    pPemBIO = BIO_new(BIO_s_mem());
    if (PEM_write_bio_ECPrivateKey(pPemBIO, ec_key, NULL, NULL, 0, NULL, NULL)!=1) {
        printf("private key error\n");
    }

    
    // 私钥转换输出
    BIO_get_mem_ptr(pPemBIO,&pBMem);
    if(pBMem->length <= nCSRSize)
    {
        memcpy(privateKey, pBMem->data, pBMem->length);
    }

    BIO_free(pPemBIO);
    
    //  验证CSR
    OpenSSL_add_all_algorithms();
    // 对签名进行验证，并传入公钥
    iRV = X509_REQ_verify(pX509Req, pEVPKey);
    if(iRV<0)
    {
        printf("verify err.\n");
    }
    
    X509_REQ_free(pX509Req);

    return nCSRSize;
}


@end
