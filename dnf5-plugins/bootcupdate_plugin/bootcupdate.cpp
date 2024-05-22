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

#include <sys/wait.h>
#include <string>

#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include <filesystem>

namespace fs = std::filesystem;
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
        int result = system("/usr/bin/bootc update");
        if (result != 0) {
           std::cerr << "Error: Command execution failed with exit code " << result << std::endl;
        } else {
            std::cout << "bootc update command executed successfully." << std::endl;
    }      
    } else {
        std::cout << "NOT managed as an immutable container." << std::endl;
    }
}

bool is_container() {
    const std::string bootc = "/usr/bin/bootc";
    const std::string ostree = "/sysroot/ostree";

    if (access(bootc.c_str(), X_OK) == 0) {
        FILE* pipe = popen((bootc + " status --json").c_str(), "r");
        if (!pipe) {
            std::cerr << "Error: Failed to execute bootc." << std::endl;
            return false;
        }

        // Read the entire JSON string into a std::string
        std::string json_output;
        char buffer[128];
        while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
            json_output += buffer;
        }
        pclose(pipe);
        if (json_output.find("\"type\":\"bootcHost\"") != std::string::npos) {
            return true;
        }
    } else if (fs::is_directory(ostree)) { 
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
