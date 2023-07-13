#ifndef _SECP256K1_MODULE_MULTISET_MAIN_
#define _SECP256K1_MODULE_MULTISET_MAIN_

//这里参考代码说明中参考资料【4】中大佬的头文件思路
//由于STD中并不是像python中有现成的椭圆曲线运算库作为底层运算
//所以这里对于底层运算部件比如secp256k1的椭圆曲线运算以及hash，有限域
//都打算分别放到其他头文件中分别调用（甚至打算用python的椭圆曲线库进行封装）
//ECMH的实现主要把注意力集中在椭圆曲线与multiset的结合上
/*include_HEADERS += include / secp256k1_multiset.h
noinst_HEADERS += src / modules / multiset / main_impl.h
noinst_HEADERS += src / modules / multiset / tests_impl.h
if USE_BENCHMARK
noinst_PROGRAMS += bench_multiset
bench_multiset_SOURCES = src / bench_multiset.c
bench_multiset_LDADD = libsecp256k1.la $(SECP_LIBS) $(COMMON_LIB)
endif
*/

#include "include/secp256k1_multiset.h"
#include "hash.h"
#include "field.h"
#include "group.h"

/* 将群元素（雅可比矩阵）转换为 multiset.
 这里也参考了【4】中大佬的思路，无限使用特殊值，z = 0 */
static void multiset_from_gej_var(secp256k1_multiset *target, const secp256k1_gej *input) {

    if (input->infinity) {
        memset(&target->d, 0, sizeof(target->d));
    }
    else {
        secp256k1_fe_get_b32(target->d, &input->x);
        secp256k1_fe_get_b32(target->d+32, &input->y);
        secp256k1_fe_get_b32(target->d+64, &input->z);
    }
}

/*将multiset转换为群元素（雅可比矩阵）
 无限使用特殊值，z = 0  */
static void gej_from_multiset_var(secp256k1_gej *target,  const secp256k1_multiset *input) {

    secp256k1_fe_set_b32(&target->x, input->d);
    secp256k1_fe_set_b32(&target->y, input->d+32);
    secp256k1_fe_set_b32(&target->z, input->d+64);

    target->infinity = secp256k1_fe_is_zero(&target->z) ? 1 : 0;
}

/*将数据元素转换为群元素（仿射）
我们使用快速但非恒定时间的trial-and-rehash
虽然存在恒定时间算法，就和说明中描述的一样
由于应用层面是UTXO Commitment所以我们不关心定时攻击
因为我们没有试图隐藏底层数据，所以可以不进行考虑*/ 
static void ge_from_data_var(secp256k1_ge *target, const unsigned char *input, size_t inputLen) {

    secp256k1_sha256_t hasher;
    unsigned char hash[32];

    /* hash to a first trial */
    secp256k1_sha256_initialize(&hasher);
    secp256k1_sha256_write(&hasher, input, inputLen);
    secp256k1_sha256_finalize(&hasher, hash);

    /* loop through trials,每轮循环的成功率为50%*/
    for(;;)
    {
        secp256k1_fe x;

        if (secp256k1_fe_set_b32(&x, hash)) {

            if (secp256k1_ge_set_xquad(target, &x)) {

                VERIFY_CHECK(secp256k1_ge_is_valid_var(target));
                VERIFY_CHECK(!secp256k1_ge_is_infinity(target));
                break;
            }
        }

        /* 新的一轮hash */
        secp256k1_sha256_initialize(&hasher);
        secp256k1_sha256_write(&hasher, hash, sizeof(hash));
        secp256k1_sha256_finalize(&hasher, hash);
    }

}


/* 向multiset中添加元素 */
int secp256k1_multiset_add(const secp256k1_context* ctx,
                              secp256k1_multiset *multiset,
                              const unsigned char *input, size_t inputLen)
{
    secp256k1_ge newelm;
    secp256k1_gej source, target;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(multiset != NULL);
    ARG_CHECK(input != NULL);

    gej_from_multiset_var(&source, multiset);
    ge_from_data_var(&newelm, input, inputLen);

    secp256k1_gej_add_ge_var(&target, &source, &newelm, NULL);

    secp256k1_fe_normalize(&target.x);
    secp256k1_fe_normalize(&target.y);
    secp256k1_fe_normalize(&target.z);
    multiset_from_gej_var(multiset, &target);

    return 1;
}

/* 从multiset中删除元素 */
int secp256k1_multiset_remove(const secp256k1_context* ctx,
                              secp256k1_multiset *multiset,
                              const unsigned char *input, size_t inputLen)
{
    secp256k1_ge newelm, neg_newelm;
    secp256k1_gej source, target;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(multiset != NULL);
    ARG_CHECK(input != NULL);

    gej_from_multiset_var(&source, multiset);
    ge_from_data_var(&newelm, input, inputLen);

    /* find inverse and add */
    secp256k1_ge_neg(&neg_newelm, &newelm);
    secp256k1_gej_add_ge_var(&target, &source, &neg_newelm, NULL);

    secp256k1_fe_normalize(&target.x);
    secp256k1_fe_normalize(&target.y);
    secp256k1_fe_normalize(&target.z);
    multiset_from_gej_var(multiset, &target);

    return 1;
}

/* 两个multiset直接相加 */
int secp256k1_multiset_combine(const secp256k1_context* ctx, secp256k1_multiset *multiset, const secp256k1_multiset *input)
{
    secp256k1_gej gej_multiset, gej_input, gej_result;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(multiset != NULL);
    ARG_CHECK(input != NULL);

    gej_from_multiset_var(&gej_multiset, multiset);
    gej_from_multiset_var(&gej_input, input);

    secp256k1_gej_add_var(&gej_result, &gej_multiset, &gej_input, NULL);

    secp256k1_fe_normalize(&gej_result.x);
    secp256k1_fe_normalize(&gej_result.y);
    secp256k1_fe_normalize(&gej_result.z);
    multiset_from_gej_var(multiset, &gej_result);

    return 1;
}


/* 对于multiset进行hash得到最终的hash结果*/
int secp256k1_multiset_finalize(const secp256k1_context* ctx, unsigned char *resultHash, const secp256k1_multiset *multiset)
{
    secp256k1_sha256_t hasher;
    unsigned char buffer[64];
    secp256k1_gej gej;
    secp256k1_ge ge;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(resultHash != NULL);
    ARG_CHECK(multiset != NULL);

    gej_from_multiset_var(&gej, multiset);
    if (gej.infinity) {

        memset(buffer, 0xff, sizeof(buffer));
    } else {
        /* 我们应该正交化仿射坐标之后再进行运算 */
        secp256k1_ge_set_gej(&ge, &gej);
        secp256k1_fe_normalize(&ge.x);
        secp256k1_fe_normalize(&ge.y);
        secp256k1_fe_get_b32(buffer, &ge.x);
        secp256k1_fe_get_b32(buffer+32, &ge.y);
    }

    secp256k1_sha256_initialize(&hasher);
    secp256k1_sha256_write(&hasher, buffer, sizeof(buffer));
    secp256k1_sha256_finalize(&hasher, resultHash);

    return 1;
}

/* 初始化具有空数据常数的multiset，由Jacobian GE infinite表示 */
int secp256k1_multiset_init(const secp256k1_context* ctx, secp256k1_multiset *multiset) {


    const secp256k1_gej inf = SECP256K1_GEJ_CONST_INFINITY;

    VERIFY_CHECK(ctx != NULL);

    multiset_from_gej_var(multiset, &inf);

    return 1;
}
#endif



//希望再写一下学习笔记中相关的安全测试的功能
//尤其是关于在mutliset操作后的乱序，拼接，删除等操作后可能引入的安全性攻击，比如碰撞，第二原象，原象等。
//重新写了用于测试的程序(没有额外上传测试程序（懒了）直接)
//花了5个多小时终于把test程序调好了，直接粘贴到trial文件的后面了
/*
#ifndef _SECP256K1_MODULE_MULTISET_TESTS_
#define _SECP256K1_MODULE_MULTISET_TESTS_


#include "include/secp256k1.h"
#include "include/secp256k1_multiset.h"
#include "util.h"
#include "testrand.h"
如果要单独运行测试程序首先需要将上面secp256k1椭圆曲线做的ECMH的cpp文件改为.h的头文件
去掉这里的注释加上这些头文件引用*/

#define DATALEN   64*3
#define DATACOUNT 100


#define CHECK_EQUAL(a,b) { \
    unsigned char hash1[32]; \
    unsigned char hash2[32]; \
    secp256k1_multiset_finalize(ctx, hash1, (a)); \
    secp256k1_multiset_finalize(ctx, hash2, (b)); \
    CHECK(memcmp(hash1,hash2,sizeof(hash1))==0); \
}

#define CHECK_NOTEQUAL(a,b) { \
    unsigned char hash1[32]; \
    unsigned char hash2[32]; \
    secp256k1_multiset_finalize(ctx, hash1, (a)); \
    secp256k1_multiset_finalize(ctx, hash2, (b)); \
    CHECK(memcmp(hash1,hash2,sizeof(hash1))!=0); \
}


static unsigned char data[DATACOUNT][DATALEN];
/*生成一个随机数 */
static void initdata(void) {
    int n,m;
    for(n=0; n < DATACOUNT; n++) {
        for(m=0; m < DATALEN/4; m++) {
            ((uint32_t*) data[n])[m] = secp256k1_rand32();
        }

    }
}

/*我们先测试对于乱序的multiset，
在椭圆曲线secp256k1上进行hash，对于两个不同的输入
输出的最终hash值是否会产生碰撞
抗碰撞实与抗第二原象实验！*/

void test_unordered(void) {

    secp256k1_multiset empty, r1,r2,r3;

    secp256k1_multiset_init(ctx, &empty);
    secp256k1_multiset_init(ctx, &r1);
    secp256k1_multiset_init(ctx, &r2);
    secp256k1_multiset_init(ctx, &r3);
//进行secp256k1上的multiset加法之后，再进行hash
 
    secp256k1_multiset_add(ctx, &r1, data[0], DATALEN);
    secp256k1_multiset_add(ctx, &r2, data[1], DATALEN);


    CHECK_NOTEQUAL(&r1,&r2);
    secp256k1_multiset_add(ctx, &r1, data[1], DATALEN);
    secp256k1_multiset_add(ctx, &r2, data[0], DATALEN);
    CHECK_EQUAL(&r1,&r2);
 //判定两个hash值是否相等

    secp256k1_multiset_init(ctx, &r1);
    secp256k1_multiset_init(ctx, &r2);
    secp256k1_multiset_init(ctx, &r3);
//判定强抗碰撞实验
    CHECK_EQUAL(&r1,&r2);
    secp256k1_multiset_add(ctx, &r1, data[0], DATALEN);
    secp256k1_multiset_add(ctx, &r1, data[1], DATALEN);
    secp256k1_multiset_add(ctx, &r1, data[2], DATALEN);

    secp256k1_multiset_add(ctx, &r2, data[2], DATALEN);
    secp256k1_multiset_add(ctx, &r2, data[0], DATALEN);
    secp256k1_multiset_add(ctx, &r2, data[1], DATALEN);

    secp256k1_multiset_add(ctx, &r3, data[1], DATALEN);
    secp256k1_multiset_add(ctx, &r3, data[0], DATALEN);
    secp256k1_multiset_add(ctx, &r3, data[2], DATALEN);
//对于给定的secp256k1参数r1生成的hash值，是否能找到碰撞
 //类似于验证其单向性是否正确！
    CHECK_EQUAL(&r1,&r2);
    CHECK_EQUAL(&r1,&r3);

    secp256k1_multiset_combine(ctx, &r3, &empty);
    CHECK_EQUAL(&r1,&r3);
    secp256k1_multiset_combine(ctx, &r3, &r2);
    CHECK_NOTEQUAL(&r1,&r3);

}
//类似的测试思路对于multiset之间组合链接之后生成的新multiset的安全测试
//以及multiset的删除操作之后新multiset的安全测试内容与上面的测试函数基本相同
void test_combine(void) {

    secp256k1_multiset empty, r1,r2,r3;

    secp256k1_multiset_init(ctx, &empty);
    secp256k1_multiset_init(ctx, &r1);
    secp256k1_multiset_init(ctx, &r2);
 //这里由于是两个链所以在进行碰撞验证的时候需要多给定一个参数！
    secp256k1_multiset_init(ctx, &r3);

    secp256k1_multiset_add(ctx, &r1, data[0], DATALEN);
    secp256k1_multiset_add(ctx, &r2, data[1], DATALEN);



    CHECK_NOTEQUAL(&r1,&r2);
    secp256k1_multiset_add(ctx, &r1, data[1], DATALEN);
    secp256k1_multiset_add(ctx, &r2, data[0], DATALEN);
    CHECK_EQUAL(&r1,&r2);

    secp256k1_multiset_init(ctx, &r1);
    secp256k1_multiset_init(ctx, &r2);
    secp256k1_multiset_init(ctx, &r3);

    CHECK_EQUAL(&r1,&r2);


    secp256k1_multiset_add(ctx, &r1, data[0], DATALEN);
    secp256k1_multiset_add(ctx, &r1, data[1], DATALEN);
    secp256k1_multiset_add(ctx, &r1, data[2], DATALEN);

    secp256k1_multiset_add(ctx, &r2, data[2], DATALEN);
    secp256k1_multiset_add(ctx, &r3, data[0], DATALEN);
    secp256k1_multiset_add(ctx, &r3, data[1], DATALEN);
    secp256k1_multiset_combine(ctx, &r2, &r3);
    CHECK_EQUAL(&r1,&r2);

    secp256k1_multiset_init(ctx, &r2);
    secp256k1_multiset_init(ctx, &r3);
    secp256k1_multiset_add(ctx, &r2, data[2], DATALEN);
    secp256k1_multiset_add(ctx, &r2, data[0], DATALEN);
    secp256k1_multiset_add(ctx, &r3, data[1], DATALEN);
    secp256k1_multiset_combine(ctx, &r2, &r3);
    CHECK_EQUAL(&r1,&r2);


    secp256k1_multiset_combine(ctx, &r2, &empty);
    CHECK_EQUAL(&r1,&r2);
    secp256k1_multiset_combine(ctx, &r2, &r1);
    CHECK_NOTEQUAL(&r1,&r2);

}


void test_remove(void) {

    secp256k1_multiset empty, r1,r2,r3;

    secp256k1_multiset_init(ctx, &empty);
    secp256k1_multiset_init(ctx, &r1);
    secp256k1_multiset_init(ctx, &r2);
    secp256k1_multiset_init(ctx, &r3);

    CHECK_EQUAL(&r1,&r2);

    secp256k1_multiset_add   (ctx, &r1, data[0], DATALEN);
    secp256k1_multiset_add   (ctx, &r1, data[1], DATALEN);
    secp256k1_multiset_add   (ctx, &r1, data[3], DATALEN);
    secp256k1_multiset_add   (ctx, &r1, data[9], DATALEN);
    secp256k1_multiset_add   (ctx, &r1, data[8], DATALEN);

    secp256k1_multiset_add   (ctx, &r2, data[1], DATALEN);
    secp256k1_multiset_add   (ctx, &r2, data[9], DATALEN);
    secp256k1_multiset_add   (ctx, &r2, data[11], DATALEN);
    secp256k1_multiset_add   (ctx, &r2, data[10], DATALEN);
    secp256k1_multiset_add   (ctx, &r2, data[0], DATALEN);
    secp256k1_multiset_remove(ctx, &r2, data[10], DATALEN);
    secp256k1_multiset_add   (ctx, &r2, data[3], DATALEN);
    secp256k1_multiset_add   (ctx, &r2, data[8], DATALEN);
    secp256k1_multiset_remove(ctx, &r2, data[11], DATALEN);

    secp256k1_multiset_add   (ctx, &r3, data[9], DATALEN);
    secp256k1_multiset_add   (ctx, &r3, data[15], DATALEN);
    secp256k1_multiset_add   (ctx, &r3, data[15], DATALEN);
    secp256k1_multiset_add   (ctx, &r3, data[1], DATALEN);
    secp256k1_multiset_add   (ctx, &r3, data[9], DATALEN);
    secp256k1_multiset_remove(ctx, &r3, data[15], DATALEN);
    secp256k1_multiset_add   (ctx, &r3, data[0], DATALEN);
    secp256k1_multiset_remove(ctx, &r3, data[15], DATALEN);
    secp256k1_multiset_remove(ctx, &r3, data[9], DATALEN);
    secp256k1_multiset_add   (ctx, &r3, data[3], DATALEN);
    secp256k1_multiset_add   (ctx, &r3, data[8], DATALEN);

    CHECK_EQUAL(&r1,&r2);
    CHECK_EQUAL(&r1,&r3);
    CHECK_NOTEQUAL(&r1,&empty);

    secp256k1_multiset_remove(ctx, &r3, data[8], DATALEN);
    CHECK_NOTEQUAL(&r1,&r3);

    secp256k1_multiset_remove(ctx, &r2, data[0], DATALEN);
    secp256k1_multiset_remove(ctx, &r2, data[9], DATALEN);
    secp256k1_multiset_remove(ctx, &r2, data[8], DATALEN);
    secp256k1_multiset_remove(ctx, &r2, data[1], DATALEN);
    secp256k1_multiset_remove(ctx, &r2, data[3], DATALEN);

    CHECK_EQUAL(&r2,&empty);

}
//判断multiset是否为空（空集也可以认为是不安全的！）
void test_empty(void) {
    secp256k1_multiset empty, r1,r2;
 
    secp256k1_multiset_init(ctx, &empty);
    secp256k1_multiset_init(ctx, &r1);
    secp256k1_multiset_init(ctx, &r2);

    CHECK_EQUAL(&empty,&r1);

    /* 空+空 = 空 */
    secp256k1_multiset_combine(ctx, &r1, &r2);
    CHECK_EQUAL(&empty, &r1);
}

void run_multiset_tests(void) {

    initdata();
    test_unordered();
    test_combine();
    test_remove();
    test_empty();

}
//#endif
//差点忘了，单独运行test程序最后需要加入endif
