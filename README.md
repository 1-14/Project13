# Project-Implement-the-above-ECMH-scheme
实施上述ECMH方案：椭圆曲线哈希族（进一步学习笔记与代码实现说明）

（说明嫌弃history功能比较麻烦，所以上传了两份代码，try作为在vs编译器中的原版，trial作为进一步功能继承。）

首先我们由课程中讲述UTXO Commitment的目前兼顾效率与安全的实现方法之一 Elliptic curve MultiSet Hash

我们在课程的学习中讨论了全节点的同步问题，为了可以让新的全节点快速启动，目前，比特币的模式下要启动一个全结点，需要下载从创世区块到最新区块所有的区块。目前，所有区块的大小约为几百G。其实用全结点去验证新交易，我们其实直接操作的是UTXO集合，看一下新的交易是否引用UTXO集合的某个UTXO。

同时经过查阅资料与UTXO的相关文档，这里给出自己的理解，UTXO集合其实就是比特币系统目前的状态，所以要启动一个全节点理论上只需要下载某个区块和该区块对应的UTXO集合即可，UTXO集合的大小约为几个G（<<几百G），其与历史数据不同，可以被消耗，所以它不会像历史数据那样线性增加。当然，这样会丢失前面所有的历史交易的记录。

然而，这里存在一个问题，如果一个用户下载了UTXO集合，怎么保证下载的UTXO集合和某个区块能够对上？这里就引入了UTXO Commitment。就是把UTXO集合的摘要写到比特币的区块上。

**UTXO Commitment的实现方式**
-
根据课程中讲述的方案与参考【1】

1.朴素的方式

按某个键排列所有UTXO，然后把他们连接起来进行哈希
这样的问题在于：
随着新区块的加入，UTXO集合中会有UTXO被消费以及新的UTXO被消费。

因此，需要重新把几G的UTXO集合重新排序，算哈希。但是这样可能会出现意料之外的问题！
比如时间开销过大（等价于对一个顺序存储的内存进行删除操作所需要的时间开销），UTXO乱序等。
因此，下面引入了哈希求和算法

2.哈希求和算法

对集合中的每个UTXO进行哈希，然后把所有的哈希加起来作为这个UTXO集合的哈希结果。每接收一个新区块，就用UTXO集合的哈希减去花费的UTXO哈希&加上新增的UTXO哈希。

![图片](https://user-images.githubusercontent.com/107350922/179759883-ceff9bc3-d5df-4f9e-8d63-0978794ca490.png)【6】

这里存在一个问题，这个算法没那么安全，假设当前UTXO集合哈希为S，我想伪造的交易为T，那么我只需要找到另外哈希值为S-T的交易即可。此处还有进一步弱化，UTXO集合的数量不确定，允许很多中排列组合，安全性进一步降低。

用hash-then-add方法去哈希集合存在的其他问题：
可以参考如下的研究论文：

https://jameshfisher.com/2018/01/09/how-to-hash-multiple-values.html

为了解决哈希求和算法引入的问题，我们采用ECMH算法进行UTXO向主链的提交

ECMH哈希算法：Elliptic curve MultiSet Hash

思路：就是把哈希映射成椭圆曲线上的点，然后利用ECC的加法，将新的UTXO set添加到主链上。

课程中进一步探究了ECMH为什么比一般的哈希求和算法要安全

更安全的意思是要达到相同的安全性，ECMH算法需要的密钥长短远远小于哈希求和算法。

与椭圆曲线类型的密钥有关，举个例子就是RSA在相同的安全性的条件下，需要的密钥长度远远长于ECC的。所以ECMH需要先映射到椭圆曲线，再继续进行同态加法【2】。

**ECMH的实现参考【3】的实现思路**
-
ECMH是一个32字节的值，它是为一组数据元素唯一确定地定义的，无论其顺序如何。

该模块允许为具有以下属性的集合计算加密安全哈希：

集合元素的顺序不影响哈希

可以将元素添加到集合中，而无需重新计算整个集合
或者从数学上来说，它是：

  交换：H（a，b）=H（b，a）

  结合：H（H（a，b，c）=H（a，H（b，c））

因此，它的行为类似于对单个元素的哈希进行异或运算，但没有异或的加密弱点。

该实现使用trial-and-increment【3】将hash值转换为secp256k1曲线上的点，该曲线用作Multiset。

然后使用该椭圆曲线类中的操作添加和删除Multiset Hash。这样进行映射的话Multiset Hash就具有了结合性和交换性（如上的数学表达）。

ECMH的安全性期望：可以防止碰撞攻击。
使用的算法容易受到 timing attacks.。因此，它不能安全地隐藏正在散列的底层数据。
For the purpose of UTXO commitments this is not relevant.【4】

**ECMH实现的具体过程**
-
由上面的分析我们进一步思考：我们找到了Multiset中元素的ECMH值（32byte）。

  Multiset的大小可以是任意，其中元素也可以是任何大小的二进制序列。同时我们规定集合元素的顺序无关紧要。

重复元素是允许的，举例说明Multiset{a}不同于Multiset Hash{a，a}。

  参考【4】中的实现思路将使用secp256k1椭圆曲线【5】，Multiset的点P（a）是secp256k1椭圆曲线上为Multiset A唯一定义的点，
  
  具体定义如下

空多集的点P（{}）被定义为曲线的无穷远点。使用以下算法计算具有单个元素P（{d}）的多集的点：设n=0，x=SHA256（n，SHA256（d））

如果x是有限域中的元素而且x^3+7是二次剩余，那么P（{d}）=(x，(1/2)* (x^3+7))否则，增加n并从2继续

我们使用椭圆曲线的群运算定义两个multisets A、B的组合点：
P（A ∪ B） =P（A）* P（B）

empty multiset的ECMH是个全0串共有32字节。非空集的ECMH是64字节值的SHA256值，该值由32字节的big-endianx坐标和其椭圆曲线上点的32字节big-endiany坐标组成。



**参考资料：**

【1】https://blog.csdn.net/weixin_34346099/article/details/92411938

【2】https://blog.csdn.net/jason_cuijiahui/article/details/86711927

【3】https://eprint.iacr.org/2009/226.pdf

【4】https://github.com/tomasvdw/secp256k1/tree/multiset/src/modules/multiset

【5】https://en.bitcoin.it/wiki/Secp256k1

【6】课程ppt文件：20220606-eth-public
