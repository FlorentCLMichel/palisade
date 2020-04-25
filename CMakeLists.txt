cmake_minimum_required (VERSION 3.5.1)

project (PALISADE C CXX)

set(INSTALL_LIB_DIR lib CACHE PATH "Installation directory for libraries")
set(INSTALL_INCLUDE_DIR include/palisade CACHE PATH "Installation directory for headers")
if(WIN32 AND NOT CYGWIN)
  set(DEF_INSTALL_CMAKE_DIR CMake)
else()
  set(DEF_INSTALL_CMAKE_DIR lib/CMake/Palisade)
endif()
set(INSTALL_CMAKE_DIR ${DEF_INSTALL_CMAKE_DIR} CACHE PATH
  "Installation directory for CMake files")

foreach(p LIB INCLUDE CMAKE)
  set(var INSTALL_${p}_DIR)
  if(NOT IS_ABSOLUTE "${${var}}")
    set(${var} "${CMAKE_INSTALL_PREFIX}/${${var}}")
  endif()
endforeach()

message("***** INSTALL IS AT ${CMAKE_INSTALL_PREFIX}; to change, run cmake with -DCMAKE_INSTALL_PREFIX=/your/path")
set (CMAKE_INSTALL_MESSAGE LAZY)

option( BUILD_UNITTESTS "Set to TRUE to build unit tests for the library" TRUE)

# determine the architecture on a Linux/Unix/macOS/MinGW system
if(CMAKE_HOST_UNIX OR MINGW)
  EXECUTE_PROCESS( COMMAND uname -m COMMAND tr -d '\n' OUTPUT_VARIABLE ARCHITECTURE )
else()
  set(ARCHITECTURE "unknown")
endif()
  
if(ARCHITECTURE)
  message("-- Architecture is " ${ARCHITECTURE})
endif()

# if no build type is chosen, set the Release mode
if( NOT CMAKE_BUILD_TYPE )
  set( CMAKE_BUILD_TYPE Release CACHE STRING
       "Choose the type of build, options are: None Debug Release RelWithDebInfo
MinSizeRel."
       FORCE )
endif()

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

find_program(TAR "gtar")
find_program(TAR "tar")

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
set(PALISADE_VERSION_MINOR 9)
set(PALISADE_VERSION_PATCH 2)
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

SET(CMAKE_INSTALL_RPATH "${LIBINSTALL}")

# add the automatically determined parts of the RPATH
# which point to directories outside the build tree to the install RPATH
SET(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)

# the RPATH to be used when installing, but only if it's not a system directory
LIST(FIND CMAKE_PLATFORM_IMPLICIT_LINK_DIRECTORIES "${LIBINSTALL}" isSystemDir)
IF("${isSystemDir}" STREQUAL "-1")
   SET(CMAKE_INSTALL_RPATH "${LIBINSTALL}")
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

# Added -Wno-parentheses -Wno-pessimizing-move for compatibility with g++ >= v9.0
if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
    if (CMAKE_CXX_COMPILER_VERSION VERSION_LESS 9.0)
		set (IGNORE_WARNINGS "")
	else()
		set (IGNORE_WARNINGS "-Wno-parentheses -Wno-pessimizing-move")
	endif()
endif()
if(APPLE AND "${CMAKE_CXX_COMPILER_ID}" MATCHES "Clang")
	set(IGNORE_WARNINGS "${IGNORE_WARNINGS} -Wno-unused-private-field -Wno-shift-op-parentheses")
endif()

set(CCOMPILEFLAGS "-Wall -Werror -O3 -DPALISADE_VERSION=${PALISADE_VERSION}")
set(CXXCOMPILEFLAGS "-Wall -Werror -O3 -DPALISADE_VERSION=${PALISADE_VERSION} ${IGNORE_WARNINGS}")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${CCOMPILEFLAGS}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${CXXCOMPILEFLAGS}")

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
install(DIRECTORY ${THIRDPARTYDIR}/cereal/include/ DESTINATION include/palisade)

include_directories( third-party/google-test/googletest third-party/google-test/googletest/include )
include_directories( ${CMAKE_CURRENT_BINARY_DIR}/third-party/include )

## for tests
if( ${BUILD_UNITTESTS} )
	set(UNITTESTMAIN ${PROJECT_SOURCE_DIR}/test/Main_TestAll.cpp)
endif()

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
	install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/third-party/lib/ DESTINATION lib
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
	install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/third-party/lib/ DESTINATION lib
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
	install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/third-party/lib/ DESTINATION lib
		FILES_MATCHING PATTERN "libtcmalloc_minimal.*")
endif()

#quad math is not supported by the compiler in ARM
if("${ARCHITECTURE}" STREQUAL "aarch64")
  set(QUADMATHLIB )
else()
  set(QUADMATHLIB -lquadmath)
endif()

if("${WITH_TCM}" STREQUAL "Y")
	set(THIRDPARTYLIBS tcmalloc)
	set(THIRDPARTYSTATICLIBS tcmalloc_static )
endif()

if("${WITH_NTL}" STREQUAL "Y")
	set(THIRDPARTYLIBS "${THIRDPARTYLIBS}" ntl gmp )
	set(THIRDPARTYSTATICLIBS "${THIRDPARTYSTATICLIBS}" ntl gmp )
	add_definitions(-DWITH_NTL)
else()
	set(THIRDPARTYLIBS "${THIRDPARTYLIBS}" "${QUADMATHLIB}")
	set(THIRDPARTYSTATICLIBS "${THIRDPARTYSTATICLIBS}" "${QUADMATHLIB}")
endif()

if("${WITH_NTL}" STREQUAL "Y" OR "${WITH_TCM}" STREQUAL "Y")
	install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/third-party/include/ DESTINATION include/palisade)
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
add_subdirectory(src/binfhe)

### build the google test handlers
if( ${BUILD_UNITTESTS} )
	add_subdirectory(third-party/google-test EXCLUDE_FROM_ALL)
endif()

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

if( ${BUILD_UNITTESTS} )
add_custom_target( testall
	DEPENDS core_tests pke_tests abe_tests signature_tests binfhe_tests
	COMMAND echo core: && unittest/core_tests -t
	COMMAND echo pke: && unittest/pke_tests -t
	COMMAND echo abe: && unittest/abe_tests -t
	COMMAND echo signature: && unittest/signature_tests -t
	COMMAND echo binfhe: && unittest/binfhe_tests -t
)
endif()

add_custom_target( allexamples
	DEPENDS allcoreexamples allpkeexamples allabeexamples allsignatureexamples allbinfheexamples
)

add_custom_target( allextras
	DEPENDS allcoreextras allpkeextras
)

add_custom_target( allmodules
	DEPENDS PALISADEcore PALISADEpke PALISADEabe PALISADEsignature PALISADEbinfhe
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

export(EXPORT PalisadeTargets FILE "${PROJECT_BINARY_DIR}/PalisadeTargets.cmake")

export(PACKAGE Palisade)

# Create the PalisadeConfig.cmake and PalisadeConfigVersion files
file(RELATIVE_PATH REL_INCLUDE_DIR "${INSTALL_CMAKE_DIR}"
   "${INSTALL_INCLUDE_DIR}")
# ... for the build tree
set(CONF_INCLUDE_DIRS "${PROJECT_SOURCE_DIR}" "${PROJECT_BINARY_DIR}")
configure_file(PalisadeConfig.cmake.in
  "${PROJECT_BINARY_DIR}/PalisadeConfig.cmake" @ONLY)
# ... for the install tree
set(CONF_INCLUDE_DIRS "\${PALISADE_CMAKE_DIR}/${REL_INCLUDE_DIR}")
configure_file(PalisadeConfig.cmake.in
  "${PROJECT_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/PalisadeConfig.cmake" @ONLY)
# ... for both
configure_file(PalisadeConfigVersion.cmake.in
  "${PROJECT_BINARY_DIR}/PalisadeConfigVersion.cmake" @ONLY)

# Install the PalisadeConfig.cmake and PalisadeConfigVersion.cmake
install(FILES
  "${PROJECT_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/PalisadeConfig.cmake"
  "${PROJECT_BINARY_DIR}/PalisadeConfigVersion.cmake"
  DESTINATION "${INSTALL_CMAKE_DIR}" COMPONENT dev)

# Install the export set for use with the install-tree
install(EXPORT PalisadeTargets DESTINATION
  "${INSTALL_CMAKE_DIR}" COMPONENT dev)

