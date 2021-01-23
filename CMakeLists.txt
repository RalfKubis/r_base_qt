r_target(r_base_qt)


forsa_requires(
        r_base
    )
    
    
################################################################################
#   external
################################################################################

r_qt_find_packages(
        Qt5Core
    )


################################################################################
#   sources
################################################################################

add_sources(.)


################################################################################
#   target
################################################################################

add_library(
        ${target}
    STATIC
        ${sources}
    )


#   target-specific properties
r_target_add_defaults(
        ${target}
    )

#   dependencies
target_link_libraries(
        ${target}
    PUBLIC
        Qt5::Core
        ${META_PROJECT_NAME}::fmt
        ${META_PROJECT_NAME}::r_base
    )

if ( CMAKE_HOST_UNIX )

    target_link_libraries(
            ${target}
        PRIVATE
            uuid
        )

endif()


if ( CMAKE_HOST_WIN32 )

    target_link_libraries(
            ${target}
        PRIVATE
            Psapi
        )

endif()
