/*
Copyright Contributors to the libdnf project.

This file is part of libdnf: https://github.com/rpm-software-management/libdnf/

Libdnf is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 2 of the License, or
(at your option) any later version.

Libdnf is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with libdnf.  If not, see <https://www.gnu.org/licenses/>.
*/

#include "bootcupdate.hpp"

#include "utils/string.hpp"

#include <dnf5/shared_options.hpp>
#include <libdnf5-cli/exception.hpp>
#include <libdnf5/rpm/package_query.hpp>
#include <libdnf5/utils/bgettext/bgettext-mark-domain.h>
#include <rpm/rpmbuild.h>
#include <rpm/rpmds.h>
#include <rpm/rpmio.h>
#include <rpm/rpmlib.h>
#include <rpm/rpmmacro.h>
#include <rpm/rpmts.h>

#include <iostream>


#include <iostream>
#include <fstream>
#include <sstream>
#include <cstdlib>
#include <unistd.h>
#include <sys/wait.h>
#include <string>


namespace dnf5 {

using namespace libdnf5::cli;

bool is_container();
void BootcUpdateCommand::set_parent_command() {
    auto * arg_parser_parent_cmd = get_session().get_argument_parser().get_root_command();
    auto * arg_parser_this_cmd = get_argument_parser_command();
    arg_parser_parent_cmd->register_command(arg_parser_this_cmd);
    arg_parser_parent_cmd->get_group("software_management_commands").register_argument(arg_parser_this_cmd);
}

void BootcUpdateCommand::set_argument_parser() {
    //auto & ctx = get_context();
    //auto & parser = ctx.get_argument_parser();
    auto & cmd = *get_argument_parser_command();
    cmd.set_description("Update image-base systems via bootc");
    if (is_container()) {
        std::cout << "System is managed as an immutable container." << std::endl;
    } else {
        std::cout << "System is not managed as an immutable container." << std::endl;
    }
}


bool is_container() {
    std::string bootc = "/usr/bin/bootc";
    std::string ostree = "/sysroot/ostree";

    // TODO forking is better?
    if (access(bootc.c_str(), X_OK) == 0) {
        pid_t pid = fork();

        if (pid == 0) {
            execl(bootc.c_str(), bootc.c_str(), "status", "--json", nullptr);
            exit(EXIT_FAILURE);
        } else if (pid > 0) {
            int status;
            waitpid(pid, &status, 0);

            if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
                std::ifstream ifs("/tmp/bootc_status.json");
                if (ifs.is_open()) {
                    std::stringstream buffer;
                    buffer << ifs.rdbuf();
                    std::string json_str = buffer.str();
                    ifs.close();

                    size_t isContainerPos = json_str.find("\"isContainer\":true");
                    if (isContainerPos != std::string::npos) {
                        size_t kindPos = json_str.find("\"kind\":\"bootchost\"", isContainerPos);
                        if (kindPos != std::string::npos)
                            return true;
                    }
                }
            }
        }
    // TODO we only warn here? And only call bootc if it is true	
    } else if (access(ostree.c_str(), F_OK) == 0) {
        return true;
    }

    return false;
}


void BootcUpdateCommand::configure() {
    if (!pkg_specs.empty()) {
        get_context().get_base().get_repo_sack()->enable_source_repos();
    }

    auto & context = get_context();
    context.set_load_system_repo(true);
    context.set_load_available_repos(Context::LoadAvailableRepos::ENABLED);
}

void BootcUpdateCommand::parse_bootcupdate_specs(int specs_count, const char * const specs[]) {
    const std::string_view ext_spec(".spec");
    const std::string_view ext_srpm(".src.rpm");
    const std::string_view ext_nosrpm(".nosrc.rpm");
    std::set<std::string> unique_items;
    for (int i = 0; i < specs_count; ++i) {
        const std::string_view spec(specs[i]);
        if (auto [it, inserted] = unique_items.emplace(spec); inserted) {
            // TODO(mblaha): download remote URLs to temporary location + remove them afterwards
            if (spec.ends_with(ext_spec)) {
                spec_file_paths.emplace_back(spec);
            } else if (spec.ends_with(ext_srpm) || spec.ends_with(ext_nosrpm)) {
                srpm_file_paths.emplace_back(spec);
            } else {
                pkg_specs.emplace_back(spec);
            }
        }
    }
}

bool BootcUpdateCommand::add_from_spec_file(
    std::set<std::string> & install_specs, std::set<std::string> & conflicts_specs, const char * spec_file_name) {
    auto spec = rpmSpecParse(spec_file_name, RPMSPEC_ANYARCH | RPMSPEC_FORCE, nullptr);
    if (spec == nullptr) {
        std::cerr << "Failed to parse spec file \"" << spec_file_name << "\"." << std::endl;
        return false;
    }
    auto dependency_set = rpmdsInit(rpmSpecDS(spec, RPMTAG_REQUIRENAME));
    while (rpmdsNext(dependency_set) >= 0) {
        install_specs.emplace(rpmdsDNEVR(dependency_set) + 2);
    }
    rpmdsFree(dependency_set);
    auto conflicts_set = rpmdsInit(rpmSpecDS(spec, RPMTAG_CONFLICTNAME));
    while (rpmdsNext(conflicts_set) >= 0) {
        conflicts_specs.emplace(rpmdsDNEVR(conflicts_set) + 2);
    }
    rpmdsFree(conflicts_set);
    rpmSpecFree(spec);
    return true;
}

bool BootcUpdateCommand::add_from_srpm_file(
    std::set<std::string> & install_specs, std::set<std::string> & conflicts_specs, const char * srpm_file_name) {
    auto fd = Fopen(srpm_file_name, "r");
    if (fd == NULL || Ferror(fd)) {
        std::cerr << "Failed to open \"" << srpm_file_name << "\": " << Fstrerror(fd) << std::endl;
        if (fd) {
            Fclose(fd);
            fd = nullptr;
        }
        return false;
    }

    Header header;
    auto ts = rpmtsCreate();
    rpmtsSetVSFlags(ts, _RPMVSF_NOSIGNATURES | _RPMVSF_NODIGESTS);
    auto rc = rpmReadPackageFile(ts, fd, nullptr, &header);
    rpmtsFree(ts);
    Fclose(fd);
    fd = nullptr;

    if (rc == RPMRC_OK) {
        auto dependency_set = rpmdsInit(rpmdsNewPool(nullptr, header, RPMTAG_REQUIRENAME, 0));
        while (rpmdsNext(dependency_set) >= 0) {
            std::string_view reldep = rpmdsDNEVR(dependency_set) + 2;
            if (!reldep.starts_with("rpmlib(")) {
                install_specs.emplace(reldep);
            }
        }
        rpmdsFree(dependency_set);
        auto conflicts_set = rpmdsInit(rpmdsNewPool(nullptr, header, RPMTAG_CONFLICTNAME, 0));
        while (rpmdsNext(conflicts_set) >= 0) {
            conflicts_specs.emplace(rpmdsDNEVR(conflicts_set) + 2);
        }
        rpmdsFree(conflicts_set);
    } else {
        std::cerr << "Failed to read rpm file \"" << srpm_file_name << "\"." << std::endl;
    }

    headerFree(header);
    return true;
}

bool BootcUpdateCommand::add_from_pkg(
    std::set<std::string> & install_specs, std::set<std::string> & conflicts_specs, const std::string & pkg_spec) {
    auto & ctx = get_context();

    libdnf5::rpm::PackageQuery pkg_query(ctx.get_base());
    libdnf5::ResolveSpecSettings settings;
    settings.set_with_provides(false);
    settings.set_with_filenames(false);
    settings.set_with_binaries(false);
    settings.set_expand_globs(false);
    pkg_query.resolve_pkg_spec(pkg_spec, settings, false);

    std::vector<std::string> source_names{pkg_spec};
    for (const auto & pkg : pkg_query) {
        source_names.emplace_back(pkg.get_source_name());
    }

    libdnf5::rpm::PackageQuery source_pkgs(ctx.get_base());
    source_pkgs.filter_arch(std::vector<std::string>{"src", "nosrc"});
    source_pkgs.filter_name(source_names);
    if (source_pkgs.empty()) {
        std::cerr << "No package matched \"" << pkg_spec << "\"." << std::endl;
        return false;
    } else {
        for (const auto & pkg : source_pkgs) {
            for (const auto & reldep : pkg.get_requires()) {
                install_specs.emplace(reldep.to_string());
            }
            for (const auto & reldep : pkg.get_conflicts()) {
                conflicts_specs.emplace(reldep.to_string());
            }
        }
        return true;
    }
}

void BootcUpdateCommand::run() {
    // get build dependencies from various inputs
    std::set<std::string> install_specs{};
    std::set<std::string> conflicts_specs{};
    bool parse_ok = true;

    if (spec_file_paths.size() > 0) {
        for (const auto & macro : rpm_macros) {
            rpmPushMacro(nullptr, macro.first.c_str(), nullptr, macro.second.c_str(), -1);
        }

        for (const auto & spec : spec_file_paths) {
            parse_ok &= add_from_spec_file(install_specs, conflicts_specs, spec.c_str());
        }

        for (const auto & macro : rpm_macros) {
            rpmPopMacro(nullptr, macro.first.c_str());
        }
    } else {
        if (srpm_file_paths.size() > 0 && rpm_macros.size() > 0) {
            std::cerr << "Warning: -D or --define arguments have no meaning for source rpm packages." << std::endl;
        }
    }

    for (const auto & srpm : srpm_file_paths) {
        parse_ok &= add_from_srpm_file(install_specs, conflicts_specs, srpm.c_str());
    }

    for (const auto & pkg : pkg_specs) {
        parse_ok &= add_from_pkg(install_specs, conflicts_specs, pkg);
    }

    if (!parse_ok) {
        // failed to parse some of inputs (invalid spec, no package matched...)
        throw libdnf5::cli::Error(M_("Failed to parse some inputs."));
    }

    // fill the goal with build dependencies
    auto goal = get_context().get_goal();
    goal->set_allow_erasing(allow_erasing->get_value());

    // Search only for solution in provides and files. Use buildrequire with name search might result in inconsistent
    // behavior with installing dependencies of RPMs
    libdnf5::GoalJobSettings settings;
    settings.set_with_nevra(false);
    settings.set_with_binaries(false);

    // Don't expand globs in pkg specs. The special characters in a pkg spec
    // such as the brackets in `python3dist(build[virtualenv])`, should be
    // treated as literal.
    settings.set_expand_globs(false);

    for (const auto & spec : install_specs) {
        if (libdnf5::rpm::Reldep::is_rich_dependency(spec)) {
            goal->add_provide_install(spec);
        } else {
            // File provides could be satisfied by standard provides or files. With DNF5 we have to test both because
            // we do not download filelists and some files could be explicitly mentioned in provide section. The best
            // solution would be to merge result of provide and file search to prevent problems caused by modification
            // during distro lifecycle.
            goal->add_rpm_install(spec, settings);
        }
    }

    if (conflicts_specs.size() > 0) {
        auto & ctx = get_context();
        // exclude available (not installed) conflicting packages
        auto system_repo = ctx.get_base().get_repo_sack()->get_system_repo();
        auto rpm_package_sack = ctx.get_base().get_rpm_package_sack();
        libdnf5::rpm::PackageQuery conflicts_query_available(ctx.get_base());
        conflicts_query_available.filter_name(std::vector<std::string>{conflicts_specs.begin(), conflicts_specs.end()});
        libdnf5::rpm::PackageQuery conflicts_query_installed(conflicts_query_available);
        conflicts_query_available.filter_repo_id({system_repo->get_id()}, libdnf5::sack::QueryCmp::NEQ);
        rpm_package_sack->add_user_excludes(conflicts_query_available);

        // remove already installed conflicting packages
        conflicts_query_installed.filter_repo_id({system_repo->get_id()});
        goal->add_rpm_remove(conflicts_query_installed);
    }
}

void BootcUpdateCommand::goal_resolved() {
    auto & ctx = get_context();
    auto & transaction = *ctx.get_transaction();
    auto transaction_problems = transaction.get_problems();
    if (transaction_problems != libdnf5::GoalProblem::NO_PROBLEM) {
        auto skip_unavailable = ctx.get_base().get_config().get_skip_unavailable_option().get_value();
        if (transaction_problems != libdnf5::GoalProblem::NOT_FOUND || !skip_unavailable) {
            throw GoalResolveError(transaction);
        }
    }
}

}  // namespace dnf5
