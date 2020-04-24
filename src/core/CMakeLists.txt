# includes both C++ and C files
file (GLOB_RECURSE CORE_SRC_FILES CONFIGURE_DEPENDS lib/*.c*)

include_directories( ../core/include )
include_directories( include )
include_directories( lib )

set(CORE_VERSION_MAJOR ${PALISADE_VERSION_MAJOR})
set(CORE_VERSION_MINOR ${PALISADE_VERSION_MINOR})
set(CORE_VERSION_PATCH ${PALISADE_VERSION_PATCH})
set(CORE_VERSION ${CORE_VERSION_MAJOR}.${CORE_VERSION_MINOR}.${CORE_VERSION_PATCH})

add_library(coreobj OBJECT ${CORE_SRC_FILES})
add_dependencies(coreobj third-party)
set_property(TARGET coreobj PROPERTY POSITION_INDEPENDENT_CODE 1)

add_library (PALISADEcore SHARED $<TARGET_OBJECTS:coreobj>)
set_property(TARGET PALISADEcore PROPERTY VERSION ${CORE_VERSION})
set_property(TARGET PALISADEcore PROPERTY SOVERSION ${CORE_VERSION_MAJOR})
set_property(TARGET PALISADEcore PROPERTY RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
install(TARGETS PALISADEcore
	EXPORT PalisadeTargets
	DESTINATION lib)

if( ${BUILD_STATIC} MATCHES "YES" )
	add_library (PALISADEcore_static STATIC $<TARGET_OBJECTS:coreobj>)
	set_property(TARGET PALISADEcore_static PROPERTY RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
	install(TARGETS PALISADEcore_static
		EXPORT PalisadeTargets
		DESTINATION lib)
endif()

install(DIRECTORY include/
	DESTINATION include/palisade/core)

set (CORELIBS PUBLIC PALISADEcore ${THIRDPARTYLIBS} ${OpenMP_CXX_FLAGS})

target_link_libraries (PALISADEcore ${THIRDPARTYLIBS} ${OpenMP_CXX_FLAGS})
if( ${BUILD_STATIC} MATCHES "YES" )
	target_link_libraries (PALISADEcore_static ${THIRDPARTYSTATICLIBS} ${OpenMP_CXX_FLAGS})
endif()

if( ${BUILD_UNITTESTS} )
file (GLOB CORE_TEST_SRC_FILES CONFIGURE_DEPENDS unittest/*.cpp)
set (CORE_TEST_SRC_FILES ${CORE_TEST_SRC_FILES})
add_executable( core_tests ${CORE_TEST_SRC_FILES} ${UNITTESTMAIN} )
set_property(TARGET core_tests PROPERTY RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/unittest)
target_link_libraries ( core_tests ${CORELIBS} )
endif()

set( COREAPPS "" )
file (GLOB CORE_EXAMPLES_SRC_FILES CONFIGURE_DEPENDS examples/*.cpp)
foreach (app ${CORE_EXAMPLES_SRC_FILES})
	get_filename_component ( exe ${app} NAME_WE )
	add_executable ( ${exe} ${app} )
	set_property(TARGET ${exe} PROPERTY RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin/examples/core)
	set( COREAPPS ${COREAPPS} ${exe} )
	target_link_libraries ( ${exe} ${CORELIBS} )
endforeach()

set( COREEXTRAS "" )
file (GLOB CORE_EXTRAS_SRC_FILES CONFIGURE_DEPENDS extras/*.cpp)
foreach (app ${CORE_EXTRAS_SRC_FILES})
	get_filename_component ( exe ${app} NAME_WE )
	add_executable ( ${exe} ${app} )
	set_property(TARGET ${exe} PROPERTY RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin/extras/core)
	set_property(TARGET ${exe} PROPERTY EXCLUDE_FROM_ALL True)
	set( COREEXTRAS ${COREEXTRAS} ${exe} )
	target_link_libraries ( ${exe} ${CORELIBS} )
endforeach()

add_custom_target( allcoreexamples )
add_dependencies( allcoreexamples ${COREAPPS} )

add_custom_target( allcoreextras )
add_dependencies( allcoreextras ${COREEXTRAS} )

add_custom_target( allcore )
add_dependencies( allcore PALISADEcore allcoreexamples )

if( ${BUILD_UNITTESTS} )
add_dependencies( allcore core_tests )
endif()

add_custom_command( OUTPUT coreinfocmd COMMAND echo Builds PALISADEcore and these apps: ${COREAPPS} )
add_custom_target( coreinfo DEPENDS coreinfocmd )

add_custom_command( OUTPUT runcoretests WORKING_DIRECTORY ${CMAKE_BINARY_DIR} COMMAND ${CMAKE_BINARY_DIR}/unittest/core_tests )
add_custom_target( testcore DEPENDS core_tests runcoretests )
