cmake_minimum_required(VERSION 3.0)
project(LibscapiJavaInterface)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -maes -mpclmul -msse4.1 -fPIC -march=native -O3")

SET (BOOST_ROOT $ENV{HOME}/boost_1_60_0/)
SET (BOOST_INCLUDEDIR $ENV{HOME}/boost_1_60_0/)
SET (BOOST_LIBRARYDIR $ENV{HOME}/boost_1_60_0/stage/lib)
find_package(Boost COMPONENTS system thread REQUIRED)

INCLUDE_DIRECTORIES($ENV{HOME} /usr/include/openssl  ${BOOST_INCLUDEDIR}
        /usr/lib/jvm/java-8-openjdk-amd64/include/
        /usr/lib/jvm/java-8-openjdk-amd64/include/linux/
        $ENV{HOME}/scapi/build/libscapi/lib/NTL/unix/include
        $ENV{HOME}/scapi/build/libscapi/lib/OTExtensionBristol $ENV{HOME}/scapi/build/libscapi/lib/
        $ENV{HOME}/scapi/build/libscapi/install/include)

link_directories($ENV{HOME} /usr/ssl/lib/ $ENV{HOME}/scapi/build/libscapi/install/lib ${BOOST_LIBRARYDIR})

set(SOURCE_FILES YaoProtocol.cpp GMWProtocol.cpp MaliciousYaoProtocol.cpp YaoSingleExecutionProtocol.cpp)
add_library(LibscapiJavaInterface SHARED ${SOURCE_FILES})

TARGET_LINK_LIBRARIES(LibscapiJavaInterface $ENV{HOME}/scapi/build/libscapi/scapi.a ntl gmp gmpxx blake2
        $ENV{HOME}/scapi/build/libscapi/protocols/GMW/libgmw.a
	$ENV{HOME}/scapi/build/libscapi/protocols/YaoSingleExecution/libyaoSingleExecution.a
        $ENV{HOME}/scapi/build/libscapi/protocols/MaliciousYao/lib/MaliciousYao.a
        $ENV{HOME}/scapi/build/libscapi/scapi.a
        $ENV{HOME}/scapi/build/libscapi/build/NTL/src/ntl.a
        $ENV{HOME}/scapi/build/libscapi/protocols/SemiHonestYao/SemiHonestYao.a
        OTExtensionBristol
        boost_system boost_thread boost_serialization boost_filesystem pthread crypto dl ssl z
		relic emp-tool)
