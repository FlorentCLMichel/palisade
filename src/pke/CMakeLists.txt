file (GLOB PKE_SRC_FILES CONFIGURE_DEPENDS lib/*-impl.cpp lib/scheme/*/*-impl.cpp)

include_directories( ../core/include )
include_directories( include )
include_directories( lib )

set(PKE_VERSION_MAJOR ${PALISADE_VERSION_MAJOR})
set(PKE_VERSION_MINOR ${PALISADE_VERSION_MINOR})
set(PKE_VERSION_PATCH ${PALISADE_VERSION_PATCH})
set(PKE_VERSION ${PKE_VERSION_MAJOR}.${PKE_VERSION_MINOR}.${PKE_VERSION_PATCH})

add_library (pkeobj OBJECT ${PKE_SRC_FILES})
add_dependencies(pkeobj PALISADEcore)
set_property(TARGET pkeobj PROPERTY POSITION_INDEPENDENT_CODE 1)

add_library (PALISADEpke SHARED $<TARGET_OBJECTS:pkeobj>)
set_property(TARGET PALISADEpke PROPERTY VERSION ${PKE_VERSION})
set_property(TARGET PALISADEpke PROPERTY SOVERSION ${PKE_VERSION_MAJOR})
set_property(TARGET PALISADEpke PROPERTY RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
install(TARGETS PALISADEpke
	EXPORT PalisadeTargets
	DESTINATION lib)
if( ${BUILD_STATIC} MATCHES "YES" )
	add_library (PALISADEpke_static STATIC $<TARGET_OBJECTS:pkeobj>)
	set_property(TARGET PALISADEpke_static PROPERTY RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
	install(TARGETS PALISADEpke_static
		EXPORT PalisadeTargets
		DESTINATION lib)
endif()

install(DIRECTORY include/
	DESTINATION include/palisade/pke)

set (PKELIBS PUBLIC PALISADEpke PUBLIC PALISADEcore ${THIRDPARTYLIBS} ${OpenMP_CXX_FLAGS})

target_link_libraries (PALISADEpke PUBLIC PALISADEcore ${THIRDPARTYLIBS} ${OpenMP_CXX_FLAGS})
if( ${BUILD_STATIC} MATCHES "YES" )
	target_link_libraries (PALISADEpke_static PUBLIC PALISADEcore_static ${THIRDPARTYSTATICLIBS} ${OpenMP_CXX_FLAGS})
endif()

if( ${BUILD_UNITTESTS} )
file (GLOB PKE_TEST_SRC_FILES CONFIGURE_DEPENDS unittest/*.cpp)
add_executable (pke_tests ${PKE_TEST_SRC_FILES} ${UNITTESTMAIN})
set_property(TARGET pke_tests PROPERTY RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/unittest)
target_link_libraries ( pke_tests ${PKELIBS} )
endif()

set(PKEAPPS "")
file (GLOB PKE_EXAMPLES_SRC_FILES CONFIGURE_DEPENDS examples/*.cpp)
foreach (app ${PKE_EXAMPLES_SRC_FILES})
	get_filename_component ( exe ${app} NAME_WE )
	add_executable ( ${exe} ${app} )
	set_property(TARGET ${exe} PROPERTY RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin/examples/pke)
	set( PKEAPPS ${PKEAPPS} ${exe} )
	target_link_libraries ( ${exe} ${PKELIBS} )
endforeach()

set( PKEEXTRAS "" )
file (GLOB PKE_EXTRAS_SRC_FILES CONFIGURE_DEPENDS extras/*.cpp)
foreach (app ${PKE_EXTRAS_SRC_FILES})
	get_filename_component ( exe ${app} NAME_WE )
	add_executable (${exe} ${app} )
	set_property(TARGET ${exe} PROPERTY RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin/extras/pke)
	set_property(TARGET ${exe} PROPERTY EXCLUDE_FROM_ALL True)
	set( PKEEXTRAS ${PKEEXTRAS} ${exe} )
	target_link_libraries ( ${exe} ${PKELIBS} )
endforeach()

add_custom_target( allpkeexamples )
add_dependencies( allpkeexamples ${PKEAPPS} )

add_custom_target( allpkeextras )
add_dependencies( allpkeextras ${PKEEXTRAS} )

add_custom_target( allpke )
add_dependencies( allpke PALISADEpke allpkeexamples )

if( ${BUILD_UNITTESTS} )
add_dependencies( allpke pke_tests )
endif()

add_custom_command( OUTPUT pkeinfocmd COMMAND echo Builds PALISADEpke and these apps: ${PKEAPPS} )
add_custom_target( pkeinfo DEPENDS pkeinfocmd )

add_custom_command( OUTPUT runpketests WORKING_DIRECTORY ${CMAKE_BINARY_DIR} COMMAND ${CMAKE_BINARY_DIR}/unittest/pke_tests )
add_custom_target( testpke DEPENDS pke_tests runpketests )

