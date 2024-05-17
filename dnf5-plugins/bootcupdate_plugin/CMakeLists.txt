# set gettext domain for translations
set(GETTEXT_DOMAIN dnf5-plugin-bootcupdate)
add_definitions(-DGETTEXT_DOMAIN=\"${GETTEXT_DOMAIN}\")

add_library(bootcupdate_cmd_plugin MODULE bootcupdate.cpp bootcupdate_cmd_plugin.cpp)

# disable the 'lib' prefix in order to create bootcupdate_cmd_plugin.so
set_target_properties(bootcupdate_cmd_plugin PROPERTIES PREFIX "")

find_library(RPMBUILD NAMES rpmbuild REQUIRED)
target_link_libraries(bootcupdate_cmd_plugin PRIVATE ${RPMBUILD})

pkg_check_modules(RPM REQUIRED rpm)
target_link_libraries(bootcupdate_cmd_plugin PRIVATE ${RPM_LIBRARIES})

target_link_libraries(bootcupdate_cmd_plugin PRIVATE libdnf5 libdnf5-cli)
target_link_libraries(bootcupdate_cmd_plugin PRIVATE dnf5)

install(TARGETS bootcupdate_cmd_plugin LIBRARY DESTINATION ${CMAKE_INSTALL_FULL_LIBDIR}/dnf5/plugins/)

