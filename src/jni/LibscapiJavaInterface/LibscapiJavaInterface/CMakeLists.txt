cmake_minimum_required(VERSION 3.6)
project(LibscapiJavaInterface)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -maes -mpclmul -fPIC")

SET (BOOST_ROOT $ENV{HOME}/boost_1_60_0/)
SET (BOOST_INCLUDEDIR $ENV{HOME}/boost_1_60_0/)
SET (BOOST_LIBRARYDIR $ENV{HOME}/boost_1_60_0/stage/lib)
find_package(Boost COMPONENTS system thread REQUIRED)

INCLUDE_DIRECTORIES(/usr/include/openssl $ENV{HOME} ${BOOST_INCLUDEDIR}
        /usr/lib/jvm/java-8-openjdk-amd64/include/
        /usr/lib/jvm/java-8-openjdk-amd64/include/linux/
        $ENV{HOME}/scapi/src/jni/LibscapiJavaInterface/LibscapiJavaInterface
        $ENV{HOME}/libscapi/lib/NTL/unix/include
        $ENV{HOME}/libscapi/lib/OTExtensionBristol $ENV{HOME}/libscapi/lib/
        $ENV{HOME}/libscapi/install/include)

link_directories(/usr/ssl/lib/ $ENV{HOME}/libscapi/install/lib ${BOOST_LIBRARYDIR})

set(SOURCE_FILES LibscapiJavaInterface/YaoProtocol.cpp LibscapiJavaInterface/GMWProtocol.cpp LibscapiJavaInterface/MaliciousYaoProtocol.cpp)
add_library(LibscapiJavaInterface SHARED ${SOURCE_FILES})

TARGET_LINK_LIBRARIES(LibscapiJavaInterface $ENV{HOME}/libscapi/scapi.a ntl gmp gmpxx blake2
        $ENV{HOME}/libscapi/protocols/GMW/libgmw.a
        $ENV{HOME}/libscapi/protocols/MaliciousYao/lib/MaliciousYao.a
        $ENV{HOME}/libscapi/scapi.a
        /home/moriya/libscapi/build/NTL/src/ntl.a
        $ENV{HOME}/libscapi/protocols/SemiHonestYao/SemiHonestYao.a
        OTExtensionBristol
        boost_system boost_thread boost_serialization boost_filesystem pthread crypto dl ssl z)