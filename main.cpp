/*
  使用openssl3.0生成密钥对，并且将密钥对写入本地pem文件
  最后对字符串进行加解密继续验证
*/
#include<iostream>
#include<openssl/evp.h>
#include<openssl/rsa.h>
#include<openssl/pem.h>
#include<openssl/err.h>
#include <fstream>
using namespace std;
void handleErrors()
{
	ERR_print_errors_fp(stderr);
	abort();
}
//RSA加解密
int main()
{
	//生成非对称密钥
	int ret = 0;
	EVP_PKEY* pkey = NULL;
	EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
	if (!pctx)
		handleErrors();
	if (EVP_PKEY_keygen_init(pctx) <= 0)
		handleErrors();
	//设置长度
	if (EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 2048) < 0)
		return 0;
	if (EVP_PKEY_keygen(pctx, &pkey) <= 0)
		handleErrors();
	//读取私钥
	BIO* pri = BIO_new(BIO_s_mem());
	PEM_write_bio_PrivateKey(pri, pkey,NULL,NULL,0,NULL,NULL);
	int pri_len = BIO_pending(pri);
	char * pri_key = new char[pri_len + 1];
	BIO_read(pri, pri_key, pri_len);
	pri_key[pri_len] = '\0';
	int len = strlen(pri_key);
	//读取公钥
	BIO* pub = BIO_new(BIO_s_mem());
	PEM_write_bio_PUBKEY(pub, pkey);
	int pub_len = BIO_pending(pub);
	char* pub_key = new char[pub_len + 1];
	BIO_read(pub, pub_key, pub_len);
	pub_key[pub_len] = '\0';
	//将公私钥写入本地文件
	std::ofstream writeIntoFile("private.pem");
	if (writeIntoFile.is_open())
	{
		writeIntoFile.write(pri_key, pri_len);
		writeIntoFile.close();
	}
	std::ofstream writeIpubFile("public.pem");
	if (writeIpubFile.is_open())
	{
		writeIpubFile.write(pub_key, pub_len);
		writeIpubFile.close();
	}
	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, NULL);
	if (nullptr == ctx)
		return 0;
	if (EVP_PKEY_encrypt_init(ctx) <= 0)//初始加密上下文
		return 0;
	//需要加密的内容
	unsigned char* plaintext = (unsigned char*)"Hello, OpenSSL 3.0 RSA encryption!";
	size_t plaintext_len = strlen((char*)plaintext) + 1;
	size_t   ciphertext_len ;
	if (EVP_PKEY_encrypt(ctx, NULL,&ciphertext_len, plaintext, plaintext_len) <= 0)
		return 0;
	//加密后的内容
	unsigned char* ciphertext = (unsigned char*)malloc(ciphertext_len);
	if (EVP_PKEY_encrypt(ctx, ciphertext,& ciphertext_len, plaintext, plaintext_len) <= 0)
		return 0;
	//解密
	EVP_PKEY_CTX* deactx = EVP_PKEY_CTX_new(pkey, NULL);
	if (nullptr == deactx)
		return 0;
	if (EVP_PKEY_decrypt_init(deactx) <= 0)//初始加密上下文
		return 0;
	size_t lenth ;
	if (EVP_PKEY_decrypt(deactx, NULL, &lenth, ciphertext, ciphertext_len) < 0)
		return 0;
	unsigned char* outStr = (unsigned char*)malloc(lenth);
	if (EVP_PKEY_decrypt(deactx, outStr,& lenth, ciphertext, ciphertext_len) <= 0)
		return 0;
	free(ciphertext);
	free(outStr);
	EVP_PKEY_free(pkey);
	return 0;
}
