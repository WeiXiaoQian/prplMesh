cmake_minimum_required(VERSION 2.8)

set(PROJECT_NAME bpl)
project(${PROJECT_NAME})

message("${BoldWhite}Preparing ${BoldGreen}${PROJECT_NAME}${BoldWhite} for the ${BoldGreen}${TARGET_PLATFORM}${BoldWhite} platform${ColourReset}")

# Set the base path for the current module
set(MODULE_PATH ${CMAKE_CURRENT_LIST_DIR})

# Common Sources
file(GLOB_RECURSE bpl_common_sources ${MODULE_PATH}/common/*.c*)

# Common libraries
find_package(elpp REQUIRED)

# UGW
if (TARGET_PLATFORM STREQUAL "ugw")
    
    # UGW specific includes
    include_directories(${MODULE_PATH}/ugw/cfg/cal)

    # Platform specific includes
    include_directories(${PLATFORM_INCLUDE_DIR}/libnl3)
    include_directories(${PLATFORM_BUILD_DIR}/linux-lantiq_xrx500/bridge-utils-1.4/libbridge)
    include_directories(${PLATFORM_INCLUDE_DIR})

    # libbridge 
    link_directories(${PLATFORM_BUILD_DIR}/linux-lantiq_xrx500/bridge-utils-1.4/libbridge)

    # UGW specific sources
    file(GLOB_RECURSE bpl_platform_sources ${MODULE_PATH}/ugw/*.c*)

    # UGW specific libraries
    find_package(ubus REQUIRED)
    list(APPEND BPL_LIBS ubus nl-3 nl-route-3 bridge ugwhelper msgapi cal capi blobmsg_json)

elseif (TARGET_PLATFORM STREQUAL "rdkb")

    # Platform specific includes
    include_directories(${PLATFORM_INCLUDE_DIR})
    include_directories(${PLATFORM_INCLUDE_DIR}/libnl3)
    include_directories(${PLATFORM_INCLUDE_DIR}/bridge-utils)

    if (PASSIVE_MODE)
        add_definitions(-DBPL_PASSIVE_MODE)
    endif()

    # RDKB specific sources
    file(GLOB_RECURSE bpl_platform_sources ${MODULE_PATH}/rdkb/*.c*)

    find_package(ubus REQUIRED)
    list(APPEND BPL_LIBS ubus nl-3 nl-route-3 bridge dl slibc uci)

elseif (TARGET_PLATFORM STREQUAL "linux")

    file(GLOB_RECURSE bpl_platform_sources ${MODULE_PATH}/linux/*.c*)

    set(PLATFORM_DB_PATH ${CMAKE_INSTALL_PREFIX}/share)
    set(PLATFORM_DB_PATH_TEMP /tmp)
    add_definitions(-DPLATFORM_DB_PATH="${PLATFORM_DB_PATH}/prplmesh_platform_db")
    add_definitions(-DPLATFORM_DB_PATH_TEMP="${PLATFORM_DB_PATH_TEMP}/prplmesh_platform_db")
    install(FILES "${MODULE_PATH}/linux/prplmesh_platform_db" DESTINATION ${CMAKE_INSTALL_PREFIX}/share)

elseif (TARGET_PLATFORM STREQUAL "turris-omnia")

    file(GLOB_RECURSE bpl_platform_sources ${MODULE_PATH}/linux/*.c*)

    set(PLATFORM_DB_PATH "/opt/prplmesh/share")
    set(PLATFORM_DB_PATH_TEMP "/tmp/beerocks")
    add_definitions(-DPLATFORM_DB_PATH="${PLATFORM_DB_PATH}/prplmesh_platform_db")
    add_definitions(-DPLATFORM_DB_PATH_TEMP="${PLATFORM_DB_PATH_TEMP}/prplmesh_platform_db")
    install(FILES "${MODULE_PATH}/linux/prplmesh_platform_db" DESTINATION ${CMAKE_INSTALL_PREFIX}/share)

else()

    message(WARNING "${BoldWhite}Skipping ${BoldGreen}${PROJECT_NAME}${BoldWhite} build for unsupported platform...${ColourReset}")
    return()

endif()

# Build the library
add_library(${PROJECT_NAME} SHARED ${bpl_common_sources} ${bpl_platform_sources})
set_target_properties(${PROJECT_NAME} PROPERTIES VERSION ${${PROJECT}_VERSION_STRING} SOVERSION ${${PROJECT}_VERSION_MAJOR})
target_link_libraries(${PROJECT_NAME} PRIVATE mapf::elpp common ${BPL_LIBS})

# Install
target_include_directories(${PROJECT_NAME}
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>
        $<INSTALL_INTERFACE:include>
    )

install(TARGETS ${PROJECT_NAME} EXPORT bplConfig
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    )

install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/${PROJECT_NAME})
install(EXPORT bplConfig NAMESPACE mapf:: DESTINATION lib/cmake/${PROJECT_NAME})

if(BUILD_TESTS)
  add_subdirectory(test)
endif()
