file (GLOB SIG_SRC_FILES CONFIGURE_DEPENDS lib/*-impl.cpp)

set(SIG_VERSION_MAJOR ${PALISADE_VERSION_MAJOR})
set(SIG_VERSION_MINOR ${PALISADE_VERSION_MINOR})
set(SIG_VERSION_PATCH ${PALISADE_VERSION_PATCH})
set(SIG_VERSION ${SIG_VERSION_MAJOR}.${SIG_VERSION_MINOR}.${SIG_VERSION_PATCH})

add_library(sigobj OBJECT ${SIG_SRC_FILES})
add_dependencies(sigobj PALISADEpke)
set_property(TARGET sigobj PROPERTY POSITION_INDEPENDENT_CODE 1)

add_library (PALISADEsignature SHARED $<TARGET_OBJECTS:sigobj>)
set_property(TARGET PALISADEsignature PROPERTY VERSION ${SIG_VERSION})
set_property(TARGET PALISADEsignature PROPERTY SOVERSION ${SIG_VERSION_MAJOR})
set_property(TARGET PALISADEsignature PROPERTY RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
install(TARGETS PALISADEsignature DESTINATION lib)
if( ${BUILD_STATIC} MATCHES "YES" )
	add_library (PALISADEsignature_static STATIC $<TARGET_OBJECTS:sigobj>)
	set_property(TARGET PALISADEsignature_static PROPERTY RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
	install(TARGETS PALISADEsignature_static DESTINATION lib)
endif()

target_include_directories (PALISADEsignature PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

set (SIGLIBS PUBLIC PALISADEsignature PUBLIC PALISADEcore ${THIRDPARTYLIBS} ${OpenMP_CXX_FLAGS})

target_link_libraries (PALISADEsignature PUBLIC PALISADEcore ${THIRDPARTYLIBS} ${OpenMP_CXX_FLAGS})
if( ${BUILD_STATIC} MATCHES "YES" )
	target_link_libraries (PALISADEsignature_static PUBLIC PALISADEcore_static ${THIRDPARTYSTATICLIBS} ${OpenMP_CXX_FLAGS})
endif()

file (GLOB SIG_TEST_SRC_FILES CONFIGURE_DEPENDS unittest/*.cpp)
add_executable (signature_tests ${SIG_TEST_SRC_FILES} ${UNITTESTMAIN})
set_property(TARGET signature_tests PROPERTY RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/unittest)
target_link_libraries ( signature_tests ${SIGLIBS} )

set (SIGAPPS "")
file (GLOB SIG_DEMO_SRC_FILES CONFIGURE_DEPENDS demo/*.cpp)
foreach (app ${SIG_DEMO_SRC_FILES})
	get_filename_component ( exe ${app} NAME_WE )
	add_executable ( ${exe} ${app} )
	set_property(TARGET ${exe} PROPERTY RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin/demo/signature)
	set( SIGAPPS ${SIGAPPS} ${exe} )
	target_link_libraries ( ${exe} ${SIGLIBS} )
endforeach()

add_custom_target( allsignaturedemos )
add_dependencies( allsignaturedemos ${SIGAPPS} )

add_custom_target( allsignature )
add_dependencies( allsignature PALISADEsignature allsignaturedemos signature_tests )

add_custom_command( OUTPUT signatureinfocmd COMMAND echo Builds PALISADEsignature and these apps: ${SIGAPPS} )
add_custom_target( signatureinfo DEPENDS signatureinfocmd )

add_custom_command( OUTPUT runsignaturetests COMMAND ${CMAKE_BINARY_DIR}/unittest/signature_tests )
add_custom_target( testsignature DEPENDS signature_tests runsignaturetests )
