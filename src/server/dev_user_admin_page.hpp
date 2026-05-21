#ifndef DEV_USER_ADMIN_PAGE_HPP
#define DEV_USER_ADMIN_PAGE_HPP

#include <string>

namespace qt_server {
namespace server {

std::string build_dev_admin_login_page();
std::string build_dev_admin_overview_page();
std::string build_dev_user_admin_page();
std::string build_dev_admin_groups_page();
std::string build_dev_admin_conversations_page();
std::string build_dev_admin_sessions_page();
std::string build_dev_admin_files_page();

} // namespace server
} // namespace qt_server

#endif // DEV_USER_ADMIN_PAGE_HPP
