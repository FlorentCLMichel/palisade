file (GLOB BINFHE_SRC_FILES CONFIGURE_DEPENDS lib/*.cpp)

include_directories( ../core/include )
include_directories( ../pke/include )
include_directories( include )
include_directories( lib )

set(BINFHE_VERSION_MAJOR ${PALISADE_VERSION_MAJOR})
set(BINFHE_VERSION_MINOR ${PALISADE_VERSION_MINOR})
set(BINFHE_VERSION_PATCH ${PALISADE_VERSION_PATCH})
set(BINFHE_VERSION ${BINFHE_VERSION_MAJOR}.${BINFHE_VERSION_MINOR}.${BINFHE_VERSION_PATCH})

add_library(binfheobj OBJECT ${BINFHE_SRC_FILES})
add_dependencies(binfheobj PALISADEpke)
set_property(TARGET binfheobj PROPERTY POSITION_INDEPENDENT_CODE 1)

add_library (PALISADEbinfhe SHARED $<TARGET_OBJECTS:binfheobj>)
set_property(TARGET PALISADEbinfhe PROPERTY VERSION ${BINFHE_VERSION})
set_property(TARGET PALISADEbinfhe PROPERTY SOVERSION ${BINFHE_VERSION_MAJOR})
set_property(TARGET PALISADEbinfhe PROPERTY RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
install(TARGETS PALISADEbinfhe
	EXPORT PalisadeTargets
	DESTINATION lib)
if( ${BUILD_STATIC} MATCHES "YES" )
	add_library (PALISADEbinfhe_static STATIC $<TARGET_OBJECTS:binfheobj>)
	set_property(TARGET PALISADEbinfhe_static PROPERTY RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
	install(TARGETS PALISADEbinfhe_static
		EXPORT PalisadeTargets
		DESTINATION lib)
endif()

install(DIRECTORY include/
	DESTINATION include/palisade/binfhe)

set (BINFHELIBS PUBLIC PALISADEbinfhe PUBLIC PALISADEcore ${THIRDPARTYLIBS} ${OpenMP_CXX_FLAGS})

target_link_libraries (PALISADEbinfhe PUBLIC PALISADEcore ${THIRDPARTYLIBS} ${OpenMP_CXX_FLAGS})
if( ${BUILD_STATIC} MATCHES "YES" )
	target_link_libraries (PALISADEbinfhe_static PUBLIC PALISADEcore_static ${THIRDPARTYSTATICLIBS} ${OpenMP_CXX_FLAGS})
endif()

if( ${BUILD_UNITTESTS} )
file (GLOB BINFHE_TEST_SRC_FILES CONFIGURE_DEPENDS unittest/*.cpp)
add_executable (binfhe_tests ${BINFHE_TEST_SRC_FILES} ${UNITTESTMAIN})
set_property(TARGET binfhe_tests PROPERTY RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/unittest)
target_link_libraries ( binfhe_tests ${BINFHELIBS} )
endif()

set (BINFHEAPPS "")
file (GLOB BINFHE_EXAMPLES_SRC_FILES CONFIGURE_DEPENDS examples/*.cpp)
foreach (app ${BINFHE_EXAMPLES_SRC_FILES})
	get_filename_component ( exe ${app} NAME_WE )
	add_executable ( ${exe} ${app} )
	set_property(TARGET ${exe} PROPERTY RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin/examples/binfhe)
	set( BINFHEAPPS ${BINFHEAPPS} ${exe} )
	target_link_libraries ( ${exe} ${BINFHELIBS} )
endforeach()

add_custom_target( allbinfheexamples )
add_dependencies( allbinfheexamples ${BINFHEAPPS} )

add_custom_target( allbinfhe )
add_dependencies( allbinfhe PALISADEbinfhe allbinfheexamples )

if( ${BUILD_UNITTESTS} )
add_dependencies( allbinfhe binfhe_tests )
endif()

add_custom_command( OUTPUT binfheinfocmd COMMAND echo Builds PALISADEbinfhe and these apps: ${BINFHEAPPS} )
add_custom_target( binfheinfo DEPENDS binfheinfocmd )

add_custom_command( OUTPUT runbinfhetests WORKING_DIRECTORY ${CMAKE_BINARY_DIR} COMMAND ${CMAKE_BINARY_DIR}/unittest/binfhe_tests )
add_custom_target( testbinfhe DEPENDS binfhe_tests runbinfhetests )
