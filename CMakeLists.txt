cmake_minimum_required (VERSION 3.5.1)

# if no build type is chose, set the Release mode
if( NOT CMAKE_BUILD_TYPE )
  set( CMAKE_BUILD_TYPE Release CACHE STRING
       "Choose the type of build, options are: None Debug Release RelWithDebInfo
MinSizeRel."
       FORCE )
endif()

project (PALISADE C CXX)

set(BUILD_STATIC "NO") # set to YES to build static libs and apps
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

if("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
	message("-- Building in DEBUG mode")
else()
	message("-- Building in RELEASE mode")
endif()

string(LENGTH "${MATHBACKEND}" MATHBACKEND_LEN)

if(${MATHBACKEND_LEN} GREATER 0)
	add_definitions(-DMATHBACKEND=${MATHBACKEND})
	message ("-- MATHBACKEND is set to " ${MATHBACKEND})
endif()

if("${WITH_NTL}" STREQUAL "Y")
	message("-- NTL is turned ON")
else()
	message("-- NTL is turned OFF")	
	if(APPLE AND CMAKE_CXX_COMPILER_ID MATCHES "Clang")
		message(SEND_ERROR "***ERROR*** NTL is required for macOS/clang")
	endif()
endif()

if("${WITH_TCM}" STREQUAL "Y")
	message("-- tcmalloc is turned ON")
	if(MINGW)
		message(SEND_ERROR "***ERROR*** tcmalloc is not supported for MinGW")
	endif()
else()
	message("-- tcmalloc is turned OFF")	
endif()

set(TAR "tar")
if(APPLE)
	set(TAR "gtar")
endif()

if(APPLE)
	set(OPENMP_LIBRARIES "/usr/local/opt/libomp/lib")
	set(OPENMP_INCLUDES "/usr/local/opt/libomp/include")
endif()

OPTION (USE_OpenMP "Use OpenMP to enable <omp.h>" ON)

# Set OpenMP configuration manually for macOS
if(APPLE AND USE_OpenMP)
    if(CMAKE_C_COMPILER_ID MATCHES "Clang")
       set(OpenMP_C_FLAGS "-Xpreprocessor -fopenmp -lomp -Wno-unused-command-line-argument")
       set(OpenMP_C_LIB_NAMES "libomp")
       set(OpenMP_libomp_LIBRARY ${OpenMP_C_LIB_NAMES})
    endif()
    if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
       set(OpenMP_CXX_FLAGS "-Xpreprocessor -fopenmp -lomp -Wno-unused-command-line-argument")
       set(OpenMP_CXX_LIB_NAMES "libomp")
       set(OpenMP_libomp_LIBRARY ${OpenMP_CXX_LIB_NAMES})
    endif()
endif()
	
### several of the third-party tools use auto-make and autoconf
### we need to make sure that they are installed
execute_process(COMMAND autogen --version OUTPUT_VARIABLE AUTOGEN_VER)
# execute_process in MINGW by default does not run in a shell
if(MINGW)
	execute_process(COMMAND sh autoconf --version OUTPUT_VARIABLE AUTOCONF_VER)
else()
	execute_process(COMMAND autoconf --version OUTPUT_VARIABLE AUTOCONF_VER)	
endif()

string(LENGTH "${AUTOCONF_VER}" AUTOCONF_VER_LEN)

if( ${AUTOCONF_VER_LEN} EQUAL 0 )
	message(SEND_ERROR "Autoconf is not installed.")
endif()

set(PALISADE_VERSION_MAJOR 1)
set(PALISADE_VERSION_MINOR 6)
set(PALISADE_VERSION_PATCH 0)
set(PALISADE_VERSION ${PALISADE_VERSION_MAJOR}.${PALISADE_VERSION_MINOR}.${PALISADE_VERSION_PATCH})

if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
    # require at least gcc 6.1
    if (CMAKE_CXX_COMPILER_VERSION VERSION_LESS 6.1)
        message(FATAL_ERROR "GCC version must be at least 6.1!")
    endif()
elseif ("${CMAKE_CXX_COMPILER_ID}" MATCHES "Clang")
    # require at least clang 6
    if (CMAKE_CXX_COMPILER_VERSION VERSION_LESS 6)
        message(FATAL_ERROR "Clang version must be at least 6!")
    endif()
else()
	message(FATAL_ERROR  "You are using ${CMAKE_CXX_COMPILER_ID} version ${CMAKE_CXX_COMPILER_VERSION}, which is unsupported.")
endif()

# use, i.e. don't skip the full RPATH for the build tree
SET(CMAKE_SKIP_BUILD_RPATH  FALSE)

# when building, don't use the install RPATH already
# (but later on when installing)
SET(CMAKE_BUILD_WITH_INSTALL_RPATH FALSE)

SET(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/lib")

# add the automatically determined parts of the RPATH
# which point to directories outside the build tree to the install RPATH
SET(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)

# the RPATH to be used when installing, but only if it's not a system directory
LIST(FIND CMAKE_PLATFORM_IMPLICIT_LINK_DIRECTORIES "${CMAKE_INSTALL_PREFIX}/lib" isSystemDir)
IF("${isSystemDir}" STREQUAL "-1")
   SET(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/lib")
ENDIF("${isSystemDir}" STREQUAL "-1")

set(CMAKE_CXX_STANDARD 11)
if(APPLE)
	set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
endif()

find_package (OpenMP)

if( APPLE AND USE_OpenMP)
	include_directories("${OPENMP_INCLUDES}")
	link_directories("${OPENMP_LIBRARIES}")
	set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${OpenMP_CXX_FLAGS}")
	set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${OpenMP_C_FLAGS}")
endif()

# OpenMP_CXX_FOUND was added in cmake 3.9.x
# so we are also checking the OpenMP_FOUND flag
if (OpenMP_CXX_FOUND OR OpenMP_FOUND)
	set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${OpenMP_CXX_FLAGS}")
	set (CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${OpenMP_EXE_LINKER_FLAGS}")
	message("-- OpenMP is turned ON")
else()
	message("-- OpenMP is turned OFF")
endif()

if (OpenMP_C_FOUND)
	set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${OpenMP_C_FLAGS}")
endif()

message("***** INSTALL IS AT ${CMAKE_INSTALL_PREFIX}; to change, run cmake with -DCMAKE_INSTALL_PREFIX=/your/path")
set (CMAKE_INSTALL_MESSAGE LAZY)

# Added -Wno-parentheses -Wno-pessimizing-move for compatibility with g++ >= v9.0
if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
    if (CMAKE_CXX_COMPILER_VERSION VERSION_LESS 9.0)
		set (IGNORE_WARNINGS "")
	else()
		set (IGNORE_WARNINGS "-Wno-parentheses -Wno-pessimizing-move")
	endif()
endif()
if(APPLE AND "${CMAKE_CXX_COMPILER_ID}" MATCHES "Clang")
	set(IGNORE_WARNINGS "${IGNORE_WARNINGS} -Wno-unused-private-field")
endif()

set(COMPILEFLAGS "-Wall -Werror -O3 -DPALISADE_VERSION=${PALISADE_VERSION} ${IGNORE_WARNINGS}")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${COMPILEFLAGS}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${COMPILEFLAGS}")

find_package (Git REQUIRED)

find_package (Doxygen QUIET COMPONENTS dot)
if (DOXYGEN_FOUND)

    add_custom_target( apidocs 
        COMMAND sh -c "( cat ${CMAKE_CURRENT_SOURCE_DIR}/lbcrypto-doxy-config && echo PROJECT_NUMBER=${PALISADE_VERSION} ) | ${DOXYGEN_EXECUTABLE} -"
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMENT "Generating API documentation with Doxygen"
        VERBATIM )
	message ("-- Doxygen and dot are found")

else (DOXYGEN_FOUND)
  message("-- Doxygen and dot (from graphviz) need to be installed to generate the doxygen documentation")
endif (DOXYGEN_FOUND)

include (ExternalProject)

# third party directories
set( THIRDPARTYDIR ${CMAKE_CURRENT_SOURCE_DIR}/third-party )
include_directories( ${THIRDPARTYDIR}/include )

### Handle third-party CEREAL
include_directories( ${THIRDPARTYDIR}/cereal/include )

include_directories( src )
set (SUBMAKEFILES core pke abe signature)
foreach( dir ${SUBMAKEFILES} )
	include_directories( src/${dir}/lib )
endforeach( dir )

include_directories( third-party/google-test/googletest third-party/google-test/googletest/include )
include_directories( ${CMAKE_CURRENT_BINARY_DIR}/third-party/include )

## for tests
set(UNITTESTMAIN ${PROJECT_SOURCE_DIR}/test/Main_TestAll.cpp)

### handle third-party gmp

set(GMPSRCDIR ${THIRDPARTYDIR}/distros/gmp-6.1.2)
set(GMPLIBDIR ${CMAKE_CURRENT_BINARY_DIR}/third-party/lib)
if(MINGW)
	set(GMPLIBFILE ${GMPLIBDIR}/libgmp.dll.a)
else()
	set(GMPLIBFILE ${GMPLIBDIR}/libgmp${CMAKE_SHARED_LIBRARY_SUFFIX})
endif()

set(GMPCONF ${GMPSRCDIR}/config.h)

# unpack gmp distro

add_custom_target(
	gmp_unpack
	COMMAND cd ${THIRDPARTYDIR}/distros && ${TAR} xf gmp-6.1.2.tar.lz
	COMMAND cd ${GMPSRCDIR} && ./configure --host=${CROSS_TRIPLE} --prefix=${CMAKE_CURRENT_BINARY_DIR}/third-party --disable-static --enable-shared
)

add_custom_target(
	gmp_clobber
	COMMAND rm -fr ${THIRDPARTYDIR}/distros/gmp-6.1.2
	COMMAND rm -f "${CMAKE_CURRENT_BINARY_DIR}/third-party/lib/libgmp*"
	COMMAND rm -f "${CMAKE_CURRENT_BINARY_DIR}/third-party/include/gmp.h"
	COMMAND rm -fr "${CMAKE_CURRENT_BINARY_DIR}/third-party/share/info"
)

add_custom_target(
	gmp_all
	COMMAND make 
	COMMAND make install
	WORKING_DIRECTORY ${GMPSRCDIR}
)

add_library(gmp SHARED IMPORTED GLOBAL)
if(MINGW)
	set_target_properties(gmp PROPERTIES IMPORTED_LOCATION ${CMAKE_CURRENT_BINARY_DIR}/third-party/bin/libgmp-10.dll)
	set_target_properties(gmp PROPERTIES IMPORTED_IMPLIB ${GMPLIBFILE})
else()
	set_target_properties(gmp PROPERTIES IMPORTED_LOCATION ${GMPLIBFILE})
endif()

if("${WITH_NTL}" STREQUAL "Y")
	install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/third-party/lib DESTINATION .
		FILES_MATCHING PATTERN "libgmp.*" )
	# also copies the gmp dll file
	if(MINGW)
		install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/third-party/bin/ DESTINATION lib
			FILES_MATCHING PATTERN "libgmp*" )
	endif()
endif()

### Handle third-party libntl

set(NTLSRCDIR ${THIRDPARTYDIR}/distros/ntl-10.5.0/src)
set(NTLZIPNAME ntl-10.5.0.tar.gz)
set(NTLTARGET all)

set(NTLCONF ${NTLSRCDIR}/../include/NTL/config.h)
set(NTLLIBDIR ${CMAKE_CURRENT_BINARY_DIR}/third-party/lib)
if (MINGW)
	set(NTLLIBFILE ${NTLLIBDIR}/libntl.dll.a)
else()
	set(NTLLIBFILE ${NTLLIBDIR}/libntl${CMAKE_SHARED_LIBRARY_SUFFIX})
endif()

# unpack ntl distro

if(MINGW)
add_custom_target(
	ntl_unpack
	COMMAND cd ${THIRDPARTYDIR}/distros && ${TAR} xf ${NTLZIPNAME}
	COMMAND cd ${NTLSRCDIR} && ./configure PREFIX=${CMAKE_CURRENT_BINARY_DIR}/third-party GMP_PREFIX=${CMAKE_CURRENT_BINARY_DIR}/third-party NTL_THREADS=on NTL_THREAD_BOOST=on NTL_EXCEPTIONS=on SHARED=on NTL_STD_CXX11=on NTL_SAFE_VECTORS=off LIBTOOL_LINK_FLAGS=-no-undefined
)
else()
add_custom_target(
	ntl_unpack
	COMMAND cd ${THIRDPARTYDIR}/distros && ${TAR} xf ${NTLZIPNAME}
	COMMAND cd ${NTLSRCDIR} && ./configure PREFIX=${CMAKE_CURRENT_BINARY_DIR}/third-party GMP_PREFIX=${CMAKE_CURRENT_BINARY_DIR}/third-party NTL_THREADS=on NTL_THREAD_BOOST=on NTL_EXCEPTIONS=on SHARED=on NTL_STD_CXX11=on NTL_SAFE_VECTORS=off
)
endif()

if(MINGW)
add_custom_target(
	ntl_unpack_nowizard
	COMMAND cd ${THIRDPARTYDIR}/distros && ${TAR} xf ${NTLZIPNAME}
	COMMAND cd ${NTLSRCDIR} && ./configure PREFIX=${CMAKE_CURRENT_BINARY_DIR}/third-party GMP_PREFIX=${CMAKE_CURRENT_BINARY_DIR}/third-party NTL_THREADS=on NTL_THREAD_BOOST=on NTL_EXCEPTIONS=on SHARED=on NTL_STD_CXX11=on NTL_SAFE_VECTORS=off TUNE=generic LIBTOOL_LINK_FLAGS=-no-undefined
)
else()
add_custom_target(
	ntl_unpack_nowizard
	COMMAND cd ${THIRDPARTYDIR}/distros && ${TAR} xf ${NTLZIPNAME}
	COMMAND cd ${NTLSRCDIR} && ./configure PREFIX=${CMAKE_CURRENT_BINARY_DIR}/third-party GMP_PREFIX=${CMAKE_CURRENT_BINARY_DIR}/third-party NTL_THREADS=on NTL_THREAD_BOOST=on NTL_EXCEPTIONS=on SHARED=on NTL_STD_CXX11=on NTL_SAFE_VECTORS=off TUNE=generic
)
endif()

add_custom_target(
	ntl_clobber
	COMMAND rm -fr ${THIRDPARTYDIR}/distros/ntl-10.5.0
	COMMAND rm -f "${CMAKE_CURRENT_BINARY_DIR}/third-party/lib/libntl*"
	COMMAND rm -fr "${CMAKE_CURRENT_BINARY_DIR}/third-party/include/NTL"
	COMMAND rm -fr "${CMAKE_CURRENT_BINARY_DIR}/third-party/share/doc"
)

add_custom_target(
	ntl_all
	COMMAND make
	COMMAND make install
	WORKING_DIRECTORY ${NTLSRCDIR}
)

add_library(ntl SHARED IMPORTED GLOBAL)
if(MINGW)
set_target_properties(ntl PROPERTIES IMPORTED_LOCATION ${CMAKE_CURRENT_BINARY_DIR}/third-party/bin/libntl-35.dll)
set_target_properties(ntl PROPERTIES IMPORTED_IMPLIB ${NTLLIBFILE})
else()
set_target_properties(ntl PROPERTIES IMPORTED_LOCATION ${NTLLIBFILE})
endif()

if("${WITH_NTL}" STREQUAL "Y")
	install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/third-party/lib DESTINATION .
		FILES_MATCHING PATTERN "libntl.*" )
	# also copies the dll file
	if(MINGW)
		install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/third-party/bin/ DESTINATION lib
			FILES_MATCHING PATTERN "libntl*" )
	endif()
endif()

### Handle third-party gperftools for optional tcmalloc

add_custom_target(
	tcm
	COMMAND ./autogen.sh
	COMMAND ./configure --prefix=${CMAKE_CURRENT_BINARY_DIR}/third-party --enable-minimal
	COMMAND make
	COMMAND make install
	WORKING_DIRECTORY ${THIRDPARTYDIR}/gperftools
)

add_custom_target(
	tcm_clean
	COMMAND rm -rf include/gperftools include/google lib/libtcmalloc_minimal* lib/pkgconfig/libtcmalloc* lib/pkgconfig/libprofiler.pc share/doc/gperftools 
	WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/third-party
)

add_library(tcmalloc SHARED IMPORTED GLOBAL)
set_target_properties(tcmalloc PROPERTIES IMPORTED_LOCATION ${CMAKE_CURRENT_BINARY_DIR}/third-party/lib/libtcmalloc_minimal${CMAKE_SHARED_LIBRARY_SUFFIX})
add_library(tcmalloc_static STATIC IMPORTED GLOBAL)
set_target_properties(tcmalloc_static PROPERTIES IMPORTED_LOCATION ${CMAKE_CURRENT_BINARY_DIR}/third-party/lib/libtcmalloc_minimal${CMAKE_STATIC_LIBRARY_SUFFIX})

if("${WITH_TCM}" STREQUAL "Y")
	install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/third-party/lib DESTINATION .
		FILES_MATCHING PATTERN "libtcmalloc_minimal.*")
endif()

set(QUADMATHLIB -lquadmath)

if("${WITH_TCM}" STREQUAL "Y")
	set(THIRDPARTYLIBS PUBLIC tcmalloc)
	set(THIRDPARTYSTATICLIBS PUBLIC tcmalloc_static )
endif()

if("${WITH_NTL}" STREQUAL "Y")
	set(THIRDPARTYLIBS "${THIRDPARTYLIBS}" PUBLIC ntl PUBLIC gmp )
	set(THIRDPARTYSTATICLIBS "${THIRDPARTYSTATICLIBS}" PUBLIC ntl PUBLIC gmp )
	add_definitions(-DWITH_NTL)
else()
	set(THIRDPARTYLIBS "${THIRDPARTYLIBS}" "${QUADMATHLIB}")
	set(THIRDPARTYSTATICLIBS "${THIRDPARTYSTATICLIBS}" "${QUADMATHLIB}")
endif()

if("${WITH_NTL}" STREQUAL "Y")
	install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/third-party/include DESTINATION .)
endif()

set(DEMODATAPATH ${CMAKE_CURRENT_SOURCE_DIR}/demoData)
set(BINDEMODATAPATH ${CMAKE_CURRENT_BINARY_DIR}/demoData)

# copies demoData folder from the root of the repo to build/demoData if the folder does not exist
# also checks whether NTL and GMP have been installed if the user chose to use NTL by setting WITH_NTL=Y
if("${WITH_NTL}" STREQUAL "Y")
add_custom_target(third-party ALL
 COMMAND [ ! -f  ${GMPLIBFILE} ] && echo ***ERROR*** Be sure to run \"make gmp_unpack\" and \"make gmp_all\" || [ ! -f  ${NTLLIBFILE} ] && echo ***ERROR*** Be sure to run \"make ntl_unpack\" and \"make ntl_all\" || echo "-- NTL/GMP is already installed"
 COMMAND [ ! -d ${BINDEMODATAPATH} ] && cp -R ${DEMODATAPATH} ${BINDEMODATAPATH} && echo "-- Copied demoData files" || echo "-- demoData folder already exists"
)
else()
add_custom_target(third-party ALL
 COMMAND [ ! -d ${BINDEMODATAPATH} ] && cp -R ${DEMODATAPATH} ${BINDEMODATAPATH} && echo "-- Copied demoData files" || echo "-- demoData folder already exists"
)
endif()

# when running "make clean", additionally deletes the demoData folder and CMake cache file
SET(ADDITIONAL_CLEAN_FILES "")
LIST(APPEND ADDITIONAL_CLEAN_FILES ${BINDEMODATAPATH})
LIST(APPEND ADDITIONAL_CLEAN_FILES ${CMAKE_CURRENT_BINARY_DIR}/CMakeCache.txt)

### add each of the subdirs of src
add_subdirectory(src/core)
add_subdirectory(src/pke)
add_subdirectory(src/abe)
add_subdirectory(src/signature)

### build the google test handlers
add_subdirectory(third-party/google-test EXCLUDE_FROM_ALL)

### build the google benchmark handlers (just the parts we need)
set(BENCHMARK_ENABLE_TESTING OFF CACHE BOOL "Enable testing of the benchmark library." FORCE)
set(BENCHMARK_ENABLE_INSTALL OFF CACHE BOOL "Enable installation of benchmark. (Projects embedding benchmark may want to turn this OFF.)" FORCE)
set(BENCHMARK_ENABLE_GTEST_TESTS OFF CACHE BOOL "Enable building the unit tests which depend on gtest" FORCE)
add_subdirectory(third-party/google-benchmark EXCLUDE_FROM_ALL)

add_subdirectory(benchmark)

## clobber cleans AND cleans the third-party stuff
add_custom_target( clobber DEPENDS gmp_clobber ntl_clobber
        COMMAND make clean
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)

add_custom_target( testall
	DEPENDS core_tests pke_tests abe_tests signature_tests 
	COMMAND echo core: && unittest/core_tests -t
	COMMAND echo pke: && unittest/pke_tests -t
	COMMAND echo abe: && unittest/abe_tests -t
	COMMAND echo signature: && unittest/signature_tests -t
)

add_custom_target( alldemos 
	DEPENDS allcoredemos allpkedemos allabedemos allsignaturedemos
)

add_custom_target( allmodules
	DEPENDS PALISADEcore PALISADEpke PALISADEabe PALISADEsignature
)

# Add the additional "make clean" files
GET_DIRECTORY_PROPERTY(clean_files ADDITIONAL_MAKE_CLEAN_FILES)
LIST(APPEND            clean_files ${ADDITIONAL_CLEAN_FILES})
LIST(REMOVE_DUPLICATES clean_files)
LIST(REMOVE_ITEM       clean_files "")
SET_DIRECTORY_PROPERTIES(PROPERTIES ADDITIONAL_MAKE_CLEAN_FILES "${clean_files}")

# OpenMP_CXX_FOUND was added in cmake 3.9.x
# so we are also checking the OpenMP_FOUND flag
if (NOT (OpenMP_CXX_FOUND OR OpenMP_FOUND))
	message(SEND_ERROR "** ERROR ** OpenMP is not installed. If using macOS/clang, please run 'cmake ..' again.")
endif()
