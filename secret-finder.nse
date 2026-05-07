local http = require("http")
local shortport = require("shortport")
local stdnse = require("stdnse")

description = [[
Detects exposed sensitive files, misconfigured backups, version control
directories, environment files and private resources that may cause critical
information leakage on web servers.
]]

categories = { "discovery", "safe" }

author = "William Steven"
license = "Same as Nmap"

portrule = shortport.http

action = function(host, port)
        local results = {}
        local paths = {
                "/",
                "/admin",
                "/dashboard",
                "/login",
                "/test",
                "/robots.txt",
                "/sitemap.xml",

                "/.DS_Store",
                "/.well-known",                                                                         "/crossdomain.xml",
                "/clientaccesspolicy.xml",

                "/cgi-bin",
                "/cgi-bin/test.cgi",
                "/cgi-bin/php.cgi",
                "/cgi-bin/status",
                "/cgi-bin/admin.cgi",
                                                                                                        "/backup",
                "/bkp/",

                "/config",
                "/admin/",
                "/administrator/",
                "/admin/login",
                "/admin.php",
                "/log",
                "/private",
                "/private/",
                "/tmp",
                "/database",
                "/dev",
                "/old",
                "/new",
                "/api",
                "/assets",
                "/bin",
                "/cms",
                "/docs",
                "/downloads",
                "/email",
                "/files",
                "/forum",
                "/help",
                "/images",
                "/include",
                "/js",
                "/lib",
                "/media",
                "/news",
                "/public",
                "/scripts",
                "/server",
                "/service",
                "/sql",
                "/src",
                "/static",
                "/themes",
                "/upload",
                "/user",
                "/vendor",
                "/ws",
                "/xml",
                "/temp",
                "/debug",
                "/debug/",
        }

        local critical = {
                -- Environment & secrets
                "/.env",
                "/.env.backup",
                "/.env.bak",
                "/.env.old",

                -- Version control exposure
                "/.git",
                "/.git/",
                "/.git/config",
                "/.git/HEAD",
                "/.git/index",
                "/.git/logs/HEAD",
                "/.svn",
                "/.svn/",
                "/.hg",

                -- SSH / private keys
                "/id_rsa",
                "/id_rsa.pub",
                "/private.key",

                -- CMS / App configs
                "/wp-config.php",
                "/wp-config.php.bak",
                "/wp-config.php~",
                "/config.php",
                "/config.json",
                "/config.yml",
                "/settings.php",
                "/localsettings.php",

                -- Database dumps / backups
                "/backup.sql",
                "/backup.zip",
                "/backup.tar.gz",
                "/backup.bak",
                "/db.sql",
                "/database.sql",
                "/dump.sql",
                "/dump.tar.gz",

                -- Logs with sensitive data
                "/logs/error.log",
                "/logs/access.log",

                -- Debug / info leaks
                "/test.php",
                "/phpinfo.php",
                "/info.php",
                "/debug.log",

                -- Auth / protection files
                "/.htaccess",
                "/.htpasswd",
                "/.htaccess.bak",
                "/.htpasswd.bak",
        }

        local options = {
                redirect_ok = true,
        }

        for _, path in ipairs(paths) do
                local rsp = http.get(host, port, path)

                if rsp.status and rsp.status ~= 404 then
                        table.insert(results, string.format(" [INFO]  [%d]  %s", rsp.status, path))
                end
        end

        for _, path in ipairs(critical) do
                local rsp = http.get(host, port, path)

                if rsp.status and rsp.status ~= 404 then
                        table.insert(results, string.format(" [CRITICAL]  [%d]  %s", rsp.status, path))
                end
        end

        if #results > 0 then
                return table.concat(results, "\n")
        end
end
