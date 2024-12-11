mkdir lib
cd ./generatingLib
tar -zxvf openssl-1.1.1h.tar.gz
script_dir=$(cd `dirname $0`; pwd)
cd openssl-1.1.1h
./config shared --prefix=${script_dir}/openssl --openssldir=${script_dir}/openssl/ssl
make depend
make
make install
cd ..
rm -r ./openssl-1.1.1h
cp -r ./openssl/include/openssl/ ../include/
cp ./openssl/lib/libssl.so* ../lib/
cp ./openssl/lib/libcrypto.so* ../lib/


# paho
tar -zxvf paho.mqtt.c-1.3.9.tar.gz
cd paho.mqtt.c-1.3.9
make clean
make


cp ./build/output/libpaho-mqtt3as.so* ../../lib
cp ./src/MQTTClient*.h ./src/MQTTAsync.h ./src/MQTTProperties.h ./src/MQTTReasonCodes.h ./src/MQTTSubscribeOpts.h  ./src/MQTTExportDeclarations.h ../../include/base

# 删除遗留文件
cd ..
rm -r paho.mqtt.c-1.3.9
rm -r openssl
