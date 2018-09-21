## 聚龙链（JulongChain）平台SDK
聚龙链平台是一个基于Java的开源联盟链区块链平台。SDK是对聚龙链平台的接口调用封装。

## 环境及工具
编译环境：  <br/>
具体的环境配置请见相关文档  <br/>
集成开发环境：IntelliJ IDEA 2017.3.3  <br/>
JAVA 开发环境：JAVA JDK 1.8.0_151  <br/>
Maven依赖管理工具：Maven 3.5.2  <br/>
代码版本管理工具：GitLab  <br/>

## 编译

### 步骤：
1.从GitLab下载项目源码：打开IntelliJ IDEA,选择菜单File => New => Project from Version Control => Git  <br/>
  设置好文件夹和路径,输入Git Repository URL点后面的Test按钮测试链接成功后,点击Clone开始下载源码  <br/>
  Git Repository URL:ssh://git@gitlab.bcia.net.cn:13622/bcia/javachain-sdk-ftsafe.git  <br/>

2.添加框架支持：项目名字右键 => Add Framework Support,Java EE version选择Java EE 8,勾选Maven选项  <br/>

3.设置Project环境：选择菜单File => Project Structure… => Project,Project SDK选择已安装的JDK 1.8  <br/>
  Project language level 修改为8  <br/>
  
4.Maven导入依赖包：pom.xml右键 => Maven => Reimport  <br/>

5.编译：在Maven Projects中展开javachain-sdk-ftsafe => Lifecycle,选择双击compile编译  <br/>
<br/>

一旦您的JAVA_HOME指向安装JDK 1.8（或更高版本）并且JAVA_HOME/bin和Apache maven在您的PATH中，请发出以下命令来构建jar文件： mvn install 或者忽略单元测试 mvn install -DskipTests

## 运行单元测试
要运行单元测试，请使用mvn install运行单元测试并构建jar文件。

许多单元测试将测试失败条件导致异常和堆栈跟踪显示。这并不表示失败！

[信息]建立成功 最后通常是一个非常可靠的指示，表明所有测试都已成功通过！

## 当前版本
当前版本为0.8。

## 开源说明 <a name="license"></a>

聚龙链平台SDK使用Apache License, Version 2.0 (Apache-2.0), located in the [LICENSE](LICENSE) file.

## 端到端测试场景
用到的参数变量在/javachain-sdk-ftsafe/src/test/java/org/bcia/javachain/sdk/testutils/路径下<br/>
TestConfig.java测试参数设置<br/>
调用申请证书代码在/javachain-sdk-ftsafe/src/test/java/org/bcia/javachain_ca/sdkintegration/路径下<br/>
End2end_0_CAEnroll.java申请签发证书<br/>
调用测试代码在/javachain-sdk-ftsafe/src/test/java/org/bcia/javachain/sdkintegration/路径下<br/>
End2end_1_CreateGroup.java创建群组<br/>
End2end_2_JoinGroup.java加入群组<br/>
End2end_2_InstallSmartContract.java安装智能合约<br/>
End2end_2_InstantiateSmartContract.java实例化智能合约<br/>
End2end_3_InvokeSmartContract.java调用智能合约<br/>

## 端到端的测试环境
必须先运行julongchain ca，julongchain Node背书节点和julongchain Consenter排序节点。

## 端到端使用的文件是：
路径是javachain-sdk-ftsafe/msp<br/>
cacertsCA证书<br/>
clientkeys客户端公私钥<br/>
clientcerts客户端证书<br/>
tlsclientcerts客户端tls通道证书<br/>