include_directories( ../src/core/include )
include_directories( ../src/core/lib )
include_directories( ../src/pke/include )
include_directories( ../src/binfhe/include )

set( REGEX_FLAG -DHAVE_STD_REGEX )

if ( APPLE )
	set( WARNING_FLAG "" )
else()
	set( WARNING_FLAG -Wno-unused-but-set-variable )
endif()

set (BMLIBS PUBLIC PALISADEpke PUBLIC PALISADEbinfhe PUBLIC PALISADEcore ${THIRDPARTYLIBS} PUBLIC benchmark ${OpenMP_CXX_FLAGS})

set (BMAPPS "")
file (GLOB BMARK_SRC_FILES CONFIGURE_DEPENDS src/*.cpp)
foreach (app ${BMARK_SRC_FILES})
	get_filename_component ( exe ${app} NAME_WE )
	add_executable ( ${exe} ${app} )
	set_property(TARGET ${exe} PROPERTY RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin/benchmark)
	target_include_directories( ${exe} PUBLIC ../third-party/google-benchmark/include )
	set_target_properties( ${exe} PROPERTIES COMPILE_FLAGS
		"${REGEX_FLAG} -DHAVE_STEADY_CLOCK -DNDEBUG ${WARNING_FLAG} -Wno-unused-variable" )
	target_link_libraries ( ${exe} ${BMLIBS} )
	set (BMAPPS ${BMAPPS} ${exe})
endforeach()

add_custom_target( allbenchmark )
add_dependencies( allbenchmark ${BMAPPS} )

add_custom_command( OUTPUT benchmarkinfocmd COMMAND echo Builds benchmark lib and these apps: ${BMAPPS} )
add_custom_target( benchmarkinfo DEPENDS benchmarkinfocmd )
