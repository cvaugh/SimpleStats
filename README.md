# SimpleStats

A tool for generating easy-to-read statistics for your Apache web server. 

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
|`template`|Path to an HTML file to use as a template for the output. Leave empty to use the default template.|(empty)|
|`ignore-internal`|If true, internal requests from `127.0.0.1` or `::1` will be ignored.|`true`|
|`template-replacements`|Each of the strings in this section will be replaced by data if it is found surrounded by {{brackets}} within the template file. For example, `first-visit: abc` would cause every instance of `{{abc}}` within the template to be replaced with the time of the earliest entry in the log. Remove or comment out a key to disable it.|The value of each key is the name of the key.|
|`truncate-user-agent`|Truncate long user agents after this many characters. Set to 0 to disable truncation.|`100`|
|`show-full-agent`|If a user agent is longer than the value defined above, this determines how the full user agent can be viewed. Supported values:<br>&nbsp;&nbsp;&nbsp;`hover`: Show the full user agent when hovering over the truncated user agent<br>&nbsp;&nbsp;&nbsp;`click`: Show the full user agent in an alert (requires JavaScript)<br>&nbsp;&nbsp;&nbsp;`none`: Do not show the full user agent|`hover`|

## Command line arguments

`no-write`: Run the program as usual, but do not save the output. The default configuration file and template will still be saved.
