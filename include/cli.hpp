#ifndef PASSGUARD_CLI_HPP
#define PASSGUARD_CLI_HPP

#include <string>
#include <vector>

namespace passguard {

class CLI {
public:
    static int run(int argc, char* argv[]);

private:
    static void print_usage();

    static std::string get_flag(const std::vector<std::string>& args,
                                 const std::string& key);
    static bool has_flag(const std::vector<std::string>& args,
                          const std::string& key);

    static int cmd_init(const std::vector<std::string>& args);
    static int cmd_add(const std::vector<std::string>& args);
    static int cmd_get(const std::vector<std::string>& args);
    static int cmd_update(const std::vector<std::string>& args);
    static int cmd_delete(const std::vector<std::string>& args);
    static int cmd_list(const std::vector<std::string>& args);
    static int cmd_generate(const std::vector<std::string>& args);
};

} // namespace passguard

#endif // PASSGUARD_CLI_HPP