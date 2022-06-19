# SimpleStats

A tool for generating easy-to-read statistics for your Apache web server. 

## Configuration

The configuration for the program is stored in `~/.config/simplestats/simplestats.yml`.

#### `access-log-path`
The path to your Apache access log.
Default value: `/var/log/apache2/access.log`

#### `output-file`
The path to which the program should write its output. Changing this from the default value is recommended.
Default value: `~/simplestats.html`

#### `input-date-format`
The format of dates within the access log. See [here](https://docs.rs/chrono/latest/chrono/format/strftime/index.html) for date formatting details.
Default value: `"%d/%b/%Y:%H:%M:%S %z"`

#### `output-date-format`
The format to use for dates in the output file.
Default value: `"%e %b %Y %I:%M:%S %p"`

#### `whois-tool`
The URL of your preferred WHOIS tool. `<address>` will be replaced with the IP address.
Default value: `"https://iplocation.io/ip/<address>"`

#### `template`
Path to an HTML file to use as a template for the output. Leave empty to use the default template.
Default value: (empty)

#### `template-replacements`
Each of the strings in this section will be replaced by data if it is found surrounded by {{brackets}} within the template file. For example, `first-visit: abc` would cause every instance of `{{abc}}` within the template to be replaced with the time of the earliest entry in the log. Remove or comment out a key to disable it.
By default, the value of each key is the name of the key.

#### `truncate-user-agent`
Truncate long user agents after this many characters. Set to 0 to disable truncation.
Default value: `100`

#### `show-full-agent`
If a user agent is longer than the value defined above, this determines how the full user agent can be viewed.
Supported values:
&nbsp;&nbsp;&nbsp;`hover`: Show the full user agent when hovering over the truncated user agent
&nbsp;&nbsp;&nbsp;`click`: Show the full user agent in an alert (requires JavaScript)
&nbsp;&nbsp;&nbsp;`none`: Do not show the full user agent
Default value: `hover`
