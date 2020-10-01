##
## CMakeLists.txt for PALISADE
##
## This script will build machine-specific header files for compile
## as it generates the Makefile
##
## Note many user options are handled using an OPTION in CMake
## An option has the value of ON or OFF
## See below for the list of options

cmake_minimum_required (VERSION 3.5.1)

### To use gcc/g++ on a Macintosh, you must set the Compilers
### here, not inside the project
##if(APPLE)
##       set(CMAKE_C_COMPILER "/usr/local/bin/gcc-7")
##       set(CMAKE_CXX_COMPILER "/usr/local/bin/g++-7")
##endif()
### TODO: for now, we use CLang for Mac

project (PALISADE C CXX)

set(PALISADE_VERSION_MAJOR 1)
set(PALISADE_VERSION_MINOR 10)
set(PALISADE_VERSION_PATCH 5)
set(PALISADE_VERSION ${PALISADE_VERSION_MAJOR}.${PALISADE_VERSION_MINOR}.${PALISADE_VERSION_PATCH})

set(CMAKE_CXX_STANDARD 11)
set(CXX_STANDARD_REQUIRED ON)

#--------------------------------------------------------------------
# Build options
#--------------------------------------------------------------------
if(CMAKE_BUILD_TYPE)
  set(RELEASE_TYPES
      Debug
      Release
      RelWithDebInfo
      MinSizeRel)
  list(FIND RELEASE_TYPES ${CMAKE_BUILD_TYPE} INDEX_FOUND)
  if(${INDEX_FOUND} EQUAL -1)
    message(
      FATAL_ERROR
        "CMAKE_BUILD_TYPE must be one of Debug, Release, RelWithDebInfo, or MinSizeRel"
      )
  endif()
else()
# if no build type is chosen, default to Release mode
	set(CMAKE_BUILD_TYPE Release CACHE STRING
		"Choose the type of build, options are: None, Debug, Release, RelWithDebInfo, or
	MinSizeRel."
		FORCE )
endif()

message(STATUS "Building in ${CMAKE_BUILD_TYPE} mode" )

option( BUILD_UNITTESTS "Set to ON to build unit tests for the library" ON)
option( BUILD_EXAMPLES "Set to ON to build examples for the library" ON)
option( BUILD_BENCHMARKS "Set to ON to build benchmarks for the library" ON)
option( BUILD_EXTRAS "Set to ON to build extras for the library" OFF)
option( BUILD_STATIC "Set to ON to include static versions of the library" OFF)
option( WITH_BE2 "Include Backend 2 in build by setting WITH_BE2 to ON" ON )
option( WITH_BE4 "Include Backend 4 in build by setting WITH_BE4 to ON" ON )
option( WITH_NTL "Include Backend 6 and NTL in build by setting WITH_NTL to ON" OFF )
option( WITH_TCM "Activate tcmalloc by setting WITH_TCM to ON" OFF )
option( USE_OpenMP "Use OpenMP to enable <omp.h>" ON)
option( WITH_NATIVEOPT "Use machine-specific optimizations" OFF)
option( WITH_COVTEST "Turn on to enable coverage testing" OFF)

# Set required number of bits for native integer in build by setting NATIVE_SIZE to 64 or 128
if( NOT NATIVE_SIZE )
   set( NATIVE_SIZE 64 )
   # set( NATIVE_SIZE 128 )
endif()

### Print options
message( STATUS "BUILD_UNITTESTS:  ${BUILD_UNITTESTS}")
message( STATUS "BUILD_EXAMPLES:   ${BUILD_EXAMPLES}")
message( STATUS "BUILD_BENCHMARKS: ${BUILD_BENCHMARKS}")
message( STATUS "BUILD_EXTRAS:     ${BUILD_EXTRAS}")
message( STATUS "BUILD_STATIC:     ${BUILD_STATIC}")
message( STATUS "WITH_BE2:         ${WITH_BE2}")
message( STATUS "WITH_BE4:         ${WITH_BE4}")
message( STATUS "WITH_NTL:         ${WITH_NTL}")
message( STATUS "WITH_TCM:         ${WITH_TCM}")
message( STATUS "USE_OpenMP:       ${USE_OpenMP}")
message( STATUS "NATIVE_SIZE:      ${NATIVE_SIZE}")
message( STATUS "WITH_NATIVEOPT:   ${WITH_NATIVEOPT}")
message( STATUS "WITH_COVTEST:    ${WITH_COVTEST}")

#--------------------------------------------------------------------
# Compiler logic
#--------------------------------------------------------------------
if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
    # require at least gcc 6.1
    if (CMAKE_CXX_COMPILER_VERSION VERSION_LESS 6.1)
        message(WARNING "GCC version should be at least 6.1.")
    endif()
elseif ("${CMAKE_CXX_COMPILER_ID}" MATCHES "Clang")
    # require at least clang 6
    if (CMAKE_CXX_COMPILER_VERSION VERSION_LESS 6)
        message(WARNING "Clang version should be at least 6.")
    endif()
else()
	message(WARNING "You are using ${CMAKE_CXX_COMPILER_ID} version ${CMAKE_CXX_COMPILER_VERSION}, which is unsupported.")
endif()

# use, i.e. don't skip the full RPATH for the build tree
set(CMAKE_SKIP_BUILD_RPATH  FALSE)

# when building, don't use the install RPATH already
# (but later on when installing)
set(CMAKE_BUILD_WITH_INSTALL_RPATH FALSE)

set(CMAKE_INSTALL_RPATH "${LIBINSTALL}")

# add the automatically determined parts of the RPATH
# which point to directories outside the build tree to the install RPATH
set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)

# the RPATH to be used when installing, but only if it's not a system directory
LIST(FIND CMAKE_PLATFORM_IMPLICIT_LINK_DIRECTORIES "${LIBINSTALL}" isSystemDir)
if("${isSystemDir}" STREQUAL "-1")
   set(CMAKE_INSTALL_RPATH "${LIBINSTALL}")
endif("${isSystemDir}" STREQUAL "-1")

# Compiler flags

# Added -Wno-parentheses for compatibility with g++
if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
    set (IGNORE_WARNINGS "-Wno-parentheses")
    # we can use GNU built-in functions provided by GCC for debugging. ex: __builtin_LINE (), __builtin_FUNCTION (), __builtin_FILE ()
    add_definitions(-DBUILTIN_INFO_AVAILABLE)
    message (STATUS "BUILTIN_INFO_AVAILABLE is defined")
endif()

if("${CMAKE_CXX_COMPILER_ID}" MATCHES "Clang")
	set(IGNORE_WARNINGS "${IGNORE_WARNINGS} -Wno-unused-private-field -Wno-shift-op-parentheses")
endif()

if( WITH_NATIVEOPT )
   set (NATIVE_OPT "-march=native")
else()
   set (NATIVE_OPT "")
endif()

set(C_COMPILE_FLAGS "-Wall -Werror -O3 ${NATIVE_OPT} -DPALISADE_VERSION=${PALISADE_VERSION}")
set(CXX_COMPILE_FLAGS "-Wall -Werror -O3 ${NATIVE_OPT} -DPALISADE_VERSION=${PALISADE_VERSION} ${IGNORE_WARNINGS}")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${C_COMPILE_FLAGS}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${CXX_COMPILE_FLAGS}")

if( ${WITH_COVTEST} )
#Set flags
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} --coverage")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} --coverage")
    link_libraries(gcov)
    set( BUILDDIR ${CMAKE_CURRENT_SOURCE_DIR}/build/)
    set( COVDIR ${BUILDDIR}coverage/)
endif()

#--------------------------------------------------------------------
# Installation logic
#--------------------------------------------------------------------


### set up for install
set(INSTALL_LIB_DIR lib CACHE PATH
	"Installation directory for libraries")
set(INSTALL_INCLUDE_DIR include/palisade CACHE PATH
	"Installation directory for headers")
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

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

#--------------------------------------------------------------------
# Machine-specific checks
#--------------------------------------------------------------------
# determine the architecture on a Linux/Unix/macOS/MinGW system
if(CMAKE_HOST_UNIX OR MINGW)
  EXECUTE_PROCESS( COMMAND uname -m COMMAND tr -d '\n' OUTPUT_VARIABLE ARCHITECTURE )
else()
  set(ARCHITECTURE "unknown")
endif()

if(ARCHITECTURE)
  message(STATUS "Architecture is " ${ARCHITECTURE})
endif()

# Size checks
include(CheckTypeSize)
check_type_size("__int128" INT128)
check_type_size("uint64_t" INT64)

if( "${NATIVE_SIZE}" EQUAL 128 )
    if( ${HAVE_INT128} )
        set( NATIVEINT 128 )
        message (STATUS "NATIVEINT is set to " ${NATIVEINT})
    else()
        message(SEND_ERROR "Cannot support NATIVE_SIZE == 128")
    endif()
elseif( "${NATIVE_SIZE}" EQUAL 64 )
    if( ${HAVE_INT64} )
        set( NATIVEINT 64 )
        message (STATUS "NATIVEINT is set to " ${NATIVEINT})
    else()
        message(SEND_ERROR "Cannot support NATIVE_SIZE == 64")
    endif()
elseif( "${NATIVE_SIZE}" EQUAL 32 )
    if( ${HAVE_INT64} )
        set( NATIVEINT 32 )
        set( HAVE_INT128 FALSE)
        message (STATUS "NATIVEINT is set to " ${NATIVEINT})
    else()
        message(SEND_ERROR "Cannot support NATIVE_SIZE == 32")
    endif()
else()
    message(SEND_ERROR "NATIVE_SIZE is " ${NATIVE_SIZE})
	message(SEND_ERROR "***ERROR*** need a Native implementation")
endif()


#--------------------------------------------------------------------
# Backend logic
#--------------------------------------------------------------------
## default backend is 2
if( NOT MATHBACKEND )
	set( MATHBACKEND 2 )
endif()

message (STATUS "MATHBACKEND is set to " ${MATHBACKEND})
if( "${MATHBACKEND}" EQUAL 2 )
	if( NOT WITH_BE2 )
		message(SEND_ERROR "Cannot select backend 2 if WITH_BE2 is disabled")
	endif()
elseif( "${MATHBACKEND}" EQUAL 4 )
	if( NOT WITH_BE4 )
		message(SEND_ERROR "Cannot select backend 4 if WITH_BE4 is disabled")
	endif()
elseif( "${MATHBACKEND}" EQUAL 6 )
	if( NOT WITH_NTL )
		message(SEND_ERROR "Cannot select backend 6 if WITH_NTL is disabled")
	endif()
else()
	message(SEND_ERROR "Backend must be 2, 4 or 6")
endif()

if( "${MATHBACKEND}" EQUAL 6 AND ${NATIVEINT} EQUAL 128)
        set (MATHBACKEND 2)
        set (WITH_NTL OFF)
        message (STATUS "BACKEND 6 is not compatible with 128-bit native backend. Resetting multiprecision backend to 2.")
endif()

add_definitions(-DMATHBACKEND=${MATHBACKEND})

if(${WITH_TCM})
	message(STATUS "tcmalloc is turned ON")
	if(MINGW)
		message(SEND_ERROR "***ERROR*** tcmalloc is not supported for MinGW")
	endif()
endif()

### build configure_core.h to make options available
configure_file(./configure/config_core.in src/core/config_core.h)
install(FILES ${CMAKE_BINARY_DIR}/src/core/config_core.h DESTINATION include/palisade/core)

find_program(TAR "gtar")
find_program(TAR "tar")

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

#--------------------------------------------------------------------
# OpenMP logic
#--------------------------------------------------------------------
if (${USE_OpenMP})
	# Used to optionally compile openmp code
	add_definitions(-DPARALLEL)

	find_package (OpenMP)

	# Set OpenMP configuration manually for macOS
	if (APPLE)
		set(OPENMP_LIBRARIES "/usr/local/opt/libomp/lib")
		set(OPENMP_INCLUDES "/usr/local/opt/libomp/include")

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
	else()
		message(SEND_ERROR "** ERROR ** OpenMP is not installed. If using macOS/clang, please run 'cmake ..' again.")
	endif()

	if (OpenMP_C_FOUND OR OpenMP_FOUND)
		set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${OpenMP_C_FLAGS}")
	endif()

else() # USE_OpenMP == OFF
	find_package (Threads REQUIRED)
	# Disable unknown #pragma omp warning
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-unknown-pragmas")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-unknown-pragmas")
endif()

#--------------------------------------------------------------------
# Pthreads logic (only for Google benchmark)
#--------------------------------------------------------------------
# In order to have the Threads_FOUND on some Linux and macOS systems
set(CMAKE_THREAD_LIBS_INIT "-lpthread")
set(CMAKE_HAVE_THREADS_LIBRARY 1)
set(CMAKE_USE_WIN32_THREADS_INIT 0)
set(CMAKE_USE_PTHREADS_INIT 1)
set(THREADS_PREFER_PTHREAD_FLAG ON)

#--------------------------------------------------------------------
# Documentation logic
#--------------------------------------------------------------------
find_package (Git REQUIRED)

find_package (Doxygen QUIET COMPONENTS dot)
if (DOXYGEN_FOUND)

    add_custom_target( apidocs
        COMMAND sh -c "( cat ${CMAKE_CURRENT_SOURCE_DIR}/lbcrypto-doxy-config && echo PROJECT_NUMBER=${PALISADE_VERSION} ) | ${DOXYGEN_EXECUTABLE} -"
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMENT "Generating API documentation with Doxygen"
        VERBATIM )
	message (STATUS "Doxygen and dot are found")

else (DOXYGEN_FOUND)
  message(STATUS "Doxygen and dot (from graphviz) need to be installed to generate the doxygen documentation")
endif (DOXYGEN_FOUND)

#--------------------------------------------------------------------
# Coverage logic
#--------------------------------------------------------------------
if ( WITH_COVTEST )

    find_program(LCOV_BIN lcov)
    if (LCOV_BIN MATCHES "lcov$")
        #Creates the command make cov
            add_custom_target( cov
            DEPENDS core_tests pke_tests abe_tests signature_tests binfhe_tests #trapdoor_tests
            COMMAND cd ${BUILDDIR} && mkdir -p coverage
            COMMAND cd ${BUILDDIR}/src/core/CMakeFiles/core_tests.dir/unittest/ && gcov *.gcno && lcov --capture --directory . --output-file ${COVDIR}/core.info
            COMMAND cd ${BUILDDIR}/src/pke/CMakeFiles/pke_tests.dir/unittest/ && gcov *.gcno && lcov --capture --directory . --output-file ${COVDIR}/pke.info
            COMMAND cd ${BUILDDIR}/src/abe/CMakeFiles/abe_tests.dir/unittest/ && gcov  *.gcno && lcov --capture --directory . --output-file ${COVDIR}/abe.info
            COMMAND cd ${BUILDDIR}/src/signature/CMakeFiles/signature_tests.dir/unittest/ && gcov *.gcno && lcov --capture --directory . --output-file ${COVDIR}/signature.info
            COMMAND cd ${BUILDDIR}/src/binfhe/CMakeFiles/binfhe_tests.dir/unittest/ && gcov  *.gcno && lcov --capture --directory . --output-file ${COVDIR}/binfhe.info
            #COMMAND cd ${BUILDDIR}/src/trapdoor/CMakeFiles/trapdoor_tests.dir/unittest/ && gcov *.gcno && lcov --capture --directory . --output-file ${COVDIR}/trapdoor.info
            COMMAND cd ${COVDIR} && mkdir -p assets && genhtml -t "Coverage Test" -o ${COVDIR}/assets/ *.info
            )
        message(STATUS "lcov found in ${LCOV_BIN}")
    else ()
        message(STATUS "lcov needs to be installed to generate a coverage report")
    endif ()

endif()


#--------------------------------------------------------------------
# Third-party logic
#--------------------------------------------------------------------
include (ExternalProject)

# third party directories
set( THIRDPARTYDIR ${CMAKE_CURRENT_SOURCE_DIR}/third-party )
include_directories( ${THIRDPARTYDIR}/include )

### Handle third-party CEREAL
include_directories( ${THIRDPARTYDIR}/cereal/include )
install(DIRECTORY ${THIRDPARTYDIR}/cereal/include/ DESTINATION include/palisade)

include_directories( third-party/google-test/googletest third-party/google-test/googletest/include )
include_directories( ${CMAKE_CURRENT_BINARY_DIR}/third-party/include )
include_directories( ${CMAKE_CURRENT_BINARY_DIR}/src/core )

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

if(${WITH_NTL})
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
		COMMAND cd ${NTLSRCDIR} && ./configure PREFIX=${CMAKE_CURRENT_BINARY_DIR}/third-party GMP_PREFIX=${CMAKE_CURRENT_BINARY_DIR}/third-party NTL_THREADS=on NTL_THREAD_BOOST=on NTL_EXCEPTIONS=on SHARED=on NTL_STD_CXX11=on NTL_SAFE_VECTORS=off LIBTOOL_LINK_FLAGS=-no-undefined )
else()
	add_custom_target(
		ntl_unpack
		COMMAND cd ${THIRDPARTYDIR}/distros && ${TAR} xf ${NTLZIPNAME}
		COMMAND cd ${NTLSRCDIR} && ./configure PREFIX=${CMAKE_CURRENT_BINARY_DIR}/third-party GMP_PREFIX=${CMAKE_CURRENT_BINARY_DIR}/third-party NTL_THREADS=on NTL_THREAD_BOOST=on NTL_EXCEPTIONS=on SHARED=on NTL_STD_CXX11=on NTL_SAFE_VECTORS=off )
endif()

if(MINGW)
add_custom_target(
	ntl_unpack_nowizard
	COMMAND cd ${THIRDPARTYDIR}/distros && ${TAR} xf ${NTLZIPNAME}
	COMMAND cd ${NTLSRCDIR} && ./configure PREFIX=${CMAKE_CURRENT_BINARY_DIR}/third-party GMP_PREFIX=${CMAKE_CURRENT_BINARY_DIR}/third-party NTL_THREADS=on NTL_THREAD_BOOST=on NTL_EXCEPTIONS=on SHARED=on NTL_STD_CXX11=on NTL_SAFE_VECTORS=off TUNE=generic LIBTOOL_LINK_FLAGS=-no-undefined )
else()
add_custom_target(
	ntl_unpack_nowizard
	COMMAND cd ${THIRDPARTYDIR}/distros && ${TAR} xf ${NTLZIPNAME}
	COMMAND cd ${NTLSRCDIR} && ./configure PREFIX=${CMAKE_CURRENT_BINARY_DIR}/third-party GMP_PREFIX=${CMAKE_CURRENT_BINARY_DIR}/third-party NTL_THREADS=on NTL_THREAD_BOOST=on NTL_EXCEPTIONS=on SHARED=on NTL_STD_CXX11=on NTL_SAFE_VECTORS=off TUNE=generic)
endif()

add_custom_target(
	ntl_clobber
	COMMAND rm -fr ${THIRDPARTYDIR}/distros/ntl-10.5.0
	COMMAND rm -f "${CMAKE_CURRENT_BINARY_DIR}/third-party/lib/libntl*"
	COMMAND rm -fr "${CMAKE_CURRENT_BINARY_DIR}/third-party/include/NTL"
	COMMAND rm -fr "${CMAKE_CURRENT_BINARY_DIR}/third-party/share/doc" )

add_custom_target(
	ntl_all
	COMMAND make
	COMMAND make install
	WORKING_DIRECTORY ${NTLSRCDIR} )

add_library(ntl SHARED IMPORTED GLOBAL)
if(MINGW)
	set_target_properties(ntl PROPERTIES IMPORTED_LOCATION ${CMAKE_CURRENT_BINARY_DIR}/third-party/bin/libntl-35.dll)
	set_target_properties(ntl PROPERTIES IMPORTED_IMPLIB ${NTLLIBFILE})
else()
	set_target_properties(ntl PROPERTIES IMPORTED_LOCATION ${NTLLIBFILE})
endif()

if(${WITH_NTL})
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

if(${WITH_TCM})
	install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/third-party/lib DESTINATION .
		FILES_MATCHING PATTERN "libtcmalloc_minimal.*")
endif()

if(${WITH_TCM})
	set(THIRDPARTYLIBS tcmalloc)
	set(THIRDPARTYSTATICLIBS tcmalloc_static )
endif()

if(${WITH_NTL})
	set(THIRDPARTYLIBS "${THIRDPARTYLIBS}" ntl gmp )
	set(THIRDPARTYSTATICLIBS "${THIRDPARTYSTATICLIBS}" ntl gmp )
else()
	set(THIRDPARTYLIBS "${THIRDPARTYLIBS}" )
	set(THIRDPARTYSTATICLIBS "${THIRDPARTYSTATICLIBS}" )
endif()

if(${WITH_NTL} OR ${WITH_TCM})
	install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/third-party/include DESTINATION include/palisade/third-party/)
endif()

set(DEMODATAPATH ${CMAKE_CURRENT_SOURCE_DIR}/demoData)
set(BINDEMODATAPATH ${CMAKE_CURRENT_BINARY_DIR}/demoData)

# copies demoData folder from the root of the repo to build/demoData if the folder does not exist
# also checks whether NTL and GMP have been installed if the user chose to use NTL by setting WITH_NTL=OFF
if(${WITH_NTL})
	add_custom_target(third-party ALL
	COMMAND [ ! -f  ${GMPLIBFILE} ] && echo ***ERROR*** Be sure to run \"make gmp_unpack\" and \"make gmp_all\" || [ ! -f  ${NTLLIBFILE} ] && echo ***ERROR*** Be sure to run \"make ntl_unpack\" and \"make ntl_all\" || echo "-- NTL/GMP is already installed"
	COMMAND [ ! -d ${BINDEMODATAPATH} ] && cp -R ${DEMODATAPATH} ${BINDEMODATAPATH} && echo "-- Copied demoData files" || echo "-- demoData folder already exists" )
else()
	add_custom_target(third-party ALL
	COMMAND [ ! -d ${BINDEMODATAPATH} ] && cp -R ${DEMODATAPATH} ${BINDEMODATAPATH} && echo "-- Copied demoData files" || echo "-- demoData folder already exists" )
endif()

# when running "make clean", additionally deletes the demoData folder and CMake cache file
set(ADDITIONAL_CLEAN_FILES "")
LIST(APPEND ADDITIONAL_CLEAN_FILES ${BINDEMODATAPATH})
LIST(APPEND ADDITIONAL_CLEAN_FILES ${CMAKE_CURRENT_BINARY_DIR}/CMakeCache.txt)


## for tests
if( BUILD_UNITTESTS )
	set(UNITTESTMAIN ${PROJECT_SOURCE_DIR}/test/Main_TestAll.cpp)
endif()


### add each of the subdirs of src
add_subdirectory(src/core)
add_subdirectory(src/pke)
add_subdirectory(src/abe)
add_subdirectory(src/signature)
add_subdirectory(src/binfhe)

### build the google test handlers
###if( BUILD_UNITTESTS )
###	add_subdirectory(third-party/google-test EXCLUDE_FROM_ALL)
###endif()

### build the google benchmark handlers (just the parts we need)
if ( BUILD_BENCHMARKS )
	set(BENCHMARK_ENABLE_TESTING OFF CACHE BOOL "Enable testing of the benchmark library." FORCE)
	set(BENCHMARK_ENABLE_INSTALL OFF CACHE BOOL "Enable installation of benchmark. (Projects embedding benchmark may want to turn this OFF.)" FORCE)
	set(BENCHMARK_ENABLE_GTEST_TESTS OFF CACHE BOOL "Enable building the unit tests which depend on gtest" FORCE)
	add_subdirectory(third-party/google-benchmark EXCLUDE_FROM_ALL)
	add_subdirectory(benchmark)
endif()

## clobber cleans AND deletes the third-party stuff
add_custom_target( clobber DEPENDS gmp_clobber ntl_clobber
        COMMAND make clean
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR} )

if( BUILD_UNITTESTS )
	add_custom_target( testall
		DEPENDS core_tests pke_tests abe_tests signature_tests binfhe_tests
		COMMAND echo core: && unittest/core_tests -t || true
		COMMAND echo pke: && unittest/pke_tests -t || true
		COMMAND echo abe: && unittest/abe_tests -t || true
		COMMAND echo signature: && unittest/signature_tests -t || true
		COMMAND echo binfhe: && unittest/binfhe_tests -t )
endif()

if (BUILD_EXAMPLES)
	add_custom_target( allexamples
		DEPENDS allcoreexamples allpkeexamples allabeexamples allsignatureexamples allbinfheexamples )
endif()

if (BUILD_EXTRAS)
	add_custom_target( allextras
		DEPENDS allcoreextras allpkeextras )
endif()

add_custom_target( allmodules
	DEPENDS PALISADEcore PALISADEpke PALISADEabe PALISADEsignature PALISADEbinfhe )

# Add the additional "make clean" files
GET_DIRECTORY_PROPERTY(clean_files ADDITIONAL_MAKE_CLEAN_FILES)
LIST(APPEND            clean_files ${ADDITIONAL_CLEAN_FILES})
LIST(REMOVE_DUPLICATES clean_files)
LIST(REMOVE_ITEM       clean_files "")
SET_DIRECTORY_PROPERTIES(PROPERTIES ADDITIONAL_MAKE_CLEAN_FILES "${clean_files}")


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

