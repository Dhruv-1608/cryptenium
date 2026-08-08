#ifndef CRYPTENIUM_CLI_HPP
#define CRYPTENIUM_CLI_HPP

#include <string>
#include <vector>

namespace cryptenium {

class CLI {
public:
    static int run(int argc, char* argv[]);

private:
    static void print_usage();
    static void print_version();

    static std::string get_flag(const std::vector<std::string>& args,
                                const std::string& key);
    static bool has_flag(const std::vector<std::string>& args,
                         const std::string& key);

    static int cmd_init(const std::vector<std::string>& args);
    static int cmd_add(const std::vector<std::string>& args);
    static int cmd_get(const std::vector<std::string>& args);
    static int cmd_list(const std::vector<std::string>& args);
    static int cmd_delete(const std::vector<std::string>& args);
    static int cmd_generate(const std::vector<std::string>& args);
};

} // namespace cryptenium

#endif // CRYPTENIUM_CLI_HPP
