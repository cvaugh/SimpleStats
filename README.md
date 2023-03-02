# SimpleStats

A tool for generating easy-to-read statistics for your Apache web server.

### This project has been superseded by [cvaugh/jstats](https://github.com/cvaugh/jstats)

## Configuration

The program's configuration file can be found at `~/.config/simplestats/simplestats.yml`.
|Key|Description|Default value|
|---|-----------|-------------|
|`access-log-dir`|The path to your Apache log directory.|`/var/log/apache2`|
|`access-log-name`|The name of your access log.|`access.log`|
|`read-rotated-logs`|If you use [logrotate](https://linux.die.net/man/8/logrotate) to rotate your logs, SimpleStats can look for rotated logs in the same directory as the file above.|`true`|
|`log-format`|The format of your log. This can usually be found in `/etc/apache2/apache2.conf`. For more information, see the [documentation for mod_log_config](https://httpd.apache.org/docs/2.4/mod/mod_log_config.html).|`"%h %l %u %t \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i\""`|
|`output-file`|The path to which the program should write its output. Changing this from the default value is recommended.|`~/simplestats.html`|
|`input-date-format`|The format of dates within the access log. See [here](https://docs.rs/chrono/latest/chrono/format/strftime/index.html) for date formatting details.|`"%d/%b/%Y:%H:%M:%S %z"`|
|`output-date-format`|The format to use for dates in the output file.|`"%e %b %Y %I:%M:%S %p"`|
|`whois-tool`|The URL of your preferred WHOIS tool. `<address>` will be replaced with the IP address.|`"https://iplocation.io/ip/<address>"`|
|`ignore-internal`|If true, internal requests from a loopback address (i.e. `127.0.0.1` or `::1`) will be ignored.|`true`|
|`include-full-log`|If true, a table consisting of every entry in all of the access logs read by the program will be placed at the end of the output file. Not recommended for large logs.|`false`|
|`notify-on-malformed`|If true, the program will print a message to the standard error stream if a malformed log entry is encountered.|`false`|
|`truncate`|Truncate long strings after this many characters. Set to 0 to disable truncation.|`user-agent`: `100`<br>`request-url`: `100`<br>`request-method`: `7`<br>`request-protocol`: `8`<br>`referer`: `70`<br>`full-log`: `50`|
|`show-full-string`|If a string is longer than its maximum length as defined above, this determines how the full string can be viewed. Supported values:<br>&nbsp;&nbsp;&nbsp;`hover`: Show the full string when hovering over the truncated string<br>&nbsp;&nbsp;&nbsp;`click`: Show the full string in an alert (requires JavaScript)<br>&nbsp;&nbsp;&nbsp;`none`: Do not show the full string|`user-agent`: `hover`<br>`request-url`: `hover`<br>`request-method`: `hover`<br>`request-protocol`: `hover`<br>`referer`: `hover`<br>`full-log`: `click`|
|`truncate-append`|This string will be appended after strings that have been truncated. Remove or leave blank to disable.|`"..."`|

## Command line arguments

|Argument|Description|
|--------|-----------|
|`no-write`|Run the program as usual, but do not save the output. The default configuration file will still be saved if it does not already exist.|
