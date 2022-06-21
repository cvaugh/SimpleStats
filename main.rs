use chrono::DateTime;
use chrono::FixedOffset;
use chrono::Local;
use chrono::TimeZone;
use flate2::read::GzDecoder;
use linked_hash_map::LinkedHashMap;
use std::collections::HashMap;
use std::collections::HashSet;
use std::env::args;
use std::fs;
use std::fs::File;
use std::io::prelude::*;
use std::io::BufReader;
use std::path::Path;
use std::process;
use substring::Substring;
use yaml_rust::Yaml;
use yaml_rust::YamlLoader;

struct Entry {
	ip: String,
	user: String,
	time: DateTime<FixedOffset>,
	request: String,
	response: String,
	size: i32,
	referer: String,
	agent: String,
}

fn main() {
	let mut no_write: bool = false;
	for arg in args().skip(1) {
		if arg.to_lowercase().eq("no-write") {
			no_write = true;
		}
	}
	let template = include_bytes!("template.html");
	let default_config = include_bytes!("simplestats.yml");
	let config_dir = &shellexpand::tilde("~/.config/simplestats").to_string();
	fs::create_dir_all(config_dir).expect("Unable to create config directory");
	let config_path = Path::join(Path::new(&config_dir), "simplestats.yml");
	if !config_path.exists() {
		fs::write(&config_path, default_config).expect("Unable to write default config");
	}
	let template_path = Path::join(Path::new(&config_dir), "template.html");
	if !template_path.exists() {
		fs::write(&template_path, template).expect("Unable to write default template");
	}
	let config_contents = fs::read_to_string(&config_path);
	if config_contents.is_err() {
		eprintln!(
			"error: Unable to read config file at {:?}\nerror: Please ensure that the program has read/write access to the specified file.",
			&config_path
		);
		process::exit(1);
	}

	let config = &YamlLoader::load_from_str(&config_contents.unwrap()).unwrap()[0];

	let access_log_dir_str =
		shellexpand::tilde(config["access-log-dir"].as_str().unwrap()).to_string();

	let access_log_dir = Path::new(&access_log_dir_str);

	let access_log_name = config["access-log-name"].as_str().unwrap();

	let mut entries: Vec<Entry> = Vec::new();

	let initial_path = Path::join(&access_log_dir, &access_log_name);

	for entry in read_log(&initial_path, false, &config) {
		entries.push(entry);
	}

	if config["read-rotated-logs"].as_bool().unwrap_or(true) {
		let mut i = 0;
		loop {
			i += 1;
			let uncompressed_log_name = format!("{}.{}", &access_log_name, i);
			let compressed_log_name = format!("{}.{}.gz", &access_log_name, i);
			let uncompressed_path = Path::join(&access_log_dir, &uncompressed_log_name);
			let compressed_path = Path::join(&access_log_dir, &compressed_log_name);
			if !(uncompressed_path.exists() || compressed_path.exists()) {
				break;
			}
			if uncompressed_path.exists() {
				let e = read_log(&uncompressed_path, false, config);
				for entry in e {
					entries.push(entry);
				}
			} else if compressed_path.exists() {
				let e = read_log(&compressed_path, true, config);
				for entry in e {
					entries.push(entry);
				}
			}
		}
	}
	if !no_write {
		write_output(&entries, config);
	}
}

fn read_log(path: &Path, compressed: bool, config: &Yaml) -> Vec<Entry> {
	let keys_str = &config["log-format"].as_str().unwrap();
	let log_keys = extract_line_parts(keys_str, keys_str.chars().collect());
	let mut entries = Vec::new();
	if compressed {
		let file = File::open(path).expect(&format!(
			"Unable to open file: {}",
			&path.to_str().unwrap_or("?")
		));
		let mut reader = BufReader::new(GzDecoder::new(file));
		let mut line = String::new();
		while reader.read_line(&mut line).expect("Failed to read line") != 0 {
			if line.chars().count() == 0 {
				continue;
			}
			entries.push(parse_line(&line, &log_keys, config));
			line.clear();
		}
	} else {
		let contents = fs::read_to_string(&path);
		if contents.is_err() {
			eprintln!(
				"error: Unable to read log: {}",
				&path.to_str().unwrap_or("?")
			);
			process::exit(1);
		} else {
			for line in contents.unwrap().split("\n") {
				if line.chars().count() == 0 {
					continue;
				}
				entries.push(parse_line(&line, &log_keys, config));
			}
		}
	}
	return entries;
}

fn parse_line(line: &str, log_keys: &Vec<String>, config: &Yaml) -> Entry {
	let parts = extract_line_parts(line, line.chars().collect());
	return parse_parts(&parts, log_keys, config);
}

fn extract_line_parts(original: &str, line: Vec<char>) -> Vec<String> {
	let mut i: usize = 0;
	let mut start: usize = 0;
	let mut parts: Vec<String> = Vec::new();
	let mut quote_escape = false;
	let mut bracket_escape = false;
	let mut escaped = false;
	let mut skip = false;
	loop {
		if i >= line.len() {
			parts.push(original.substring(start, i - 1).to_string());
			break;
		}
		if !skip {
			escaped = quote_escape || bracket_escape;
		} else {
			skip = false;
		}

		if line[i] == '"' && !bracket_escape && line[i - 1] != '\\' {
			if !quote_escape {
				start += 1;
			} else {
				skip = true;
			}
			quote_escape = !quote_escape;
		} else if line[i] == '[' && !quote_escape {
			bracket_escape = true;
			start += 1;
		} else if line[i] == ']' && !quote_escape {
			bracket_escape = false;
			skip = true;
		} else if line[i] == ' ' {
			if !(quote_escape || bracket_escape) {
				if escaped {
					parts.push(original.substring(start, i - 1).to_string());
				} else {
					parts.push(original.substring(start, i).to_string());
				}
				start = i + 1;
				i += 1;
				continue;
			}
		}
		i += 1;
	}
	return parts;
}

fn parse_parts(parts: &Vec<String>, keys: &Vec<String>, config: &Yaml) -> Entry {
	let entry = Entry {
		ip: get_part("%h", parts, keys),
		user: get_part("%u", parts, keys),
		time: DateTime::parse_from_str(
			&get_part("%t", parts, keys),
			&config["input-date-format"].as_str().unwrap(),
		)
		.unwrap(),
		request: get_part("%r", parts, keys),
		response: get_part("%>s", parts, keys),
		size: get_part("%O", parts, keys).parse::<i32>().unwrap(),
		referer: get_part("%{Referer}i", parts, keys),
		agent: get_part("%{User-Agent}i", parts, keys),
	};

	return entry;
}

fn get_part(key: &str, parts: &Vec<String>, keys: &Vec<String>) -> String {
	for i in 0..parts.len() {
		if keys[i].eq(key) {
			return parts[i].clone();
		}
	}
	return String::new();
}

fn write_output(entries: &Vec<Entry>, config: &Yaml) {
	let template_config = &config["template"];
	let template_path_str = shellexpand::tilde(
		template_config
			.as_str()
			.unwrap_or("~/.config/simplestats/template.html"),
	)
	.to_string();
	let template_path = if template_config.is_null() {
		Path::new(&template_path_str)
	} else {
		Path::new(&template_path_str)
	};
	let template_lines = fs::read_to_string(&template_path);
	if template_lines.is_err() {
		eprintln!("error: Failed to read template at {:?}\nerror: Please ensure that the program has read/write access to the specified file.",
		&template_path);
		process::exit(1);
	}

	let mut template = template_lines.unwrap();
	let replacements = &config["template-replacements"].as_hash().unwrap();
	for (key, value) in replacements.into_iter() {
		template = template.replace(
			&format!("{{{{{}}}}}", value.as_str().unwrap()),
			get_output(key.as_str().unwrap(), entries, &config).as_str(),
		);
	}

	let output = shellexpand::tilde(&config["output-file"].as_str().unwrap()).to_string();

	let result = fs::write(&output, template);

	if result.is_err() {
		eprintln!(
			"Failed to write output to {}: {}",
			&output,
			result.unwrap_err()
		);
	}
}

fn get_output(key: &str, entries: &Vec<Entry>, config: &Yaml) -> String {
	let mut total_size = 0usize;
	for entry in entries {
		total_size += entry.size as usize;
	}
	match key {
		"generated-date" => {
			return Local::now()
				.format(&config["output-date-format"].as_str().unwrap())
				.to_string();
		}
		"first-visit" => {
			let mut dates: Vec<DateTime<FixedOffset>> = Vec::new();
			for entry in entries {
				dates.push(entry.time);
			}
			dates.sort_by_key(|k| k.timestamp_millis());
			return format_date_config(&dates[0], &config);
		}
		"latest-visit" => {
			let mut dates: Vec<DateTime<FixedOffset>> = Vec::new();
			for entry in entries {
				dates.push(entry.time);
			}
			dates.sort_by_key(|k| k.timestamp_millis());
			return format_date_config(&dates[dates.len() - 1], &config);
		}
		"overall-visitors" => {
			let mut count = 0;
			let mut added: Vec<String> = Vec::new();
			for entry in entries {
				if !added.contains(&entry.ip) {
					count += 1;
					added.push(entry.ip.clone());
				}
			}
			return count.to_string();
		}
		"overall-visits" => {
			return entries.len().to_string();
		}
		"overall-bandwidth" => {
			return human_readable_bytes(total_size);
		}
		"yearly-rows" => {
			let mut years: HashMap<i32, i32> = HashMap::new();
			let mut sizes: HashMap<i32, usize> = HashMap::new();
			let mut unique: HashMap<i32, HashSet<&str>> = HashMap::new();
			for entry in entries {
				let year = format_date(&entry.time, "%Y").parse::<i32>().unwrap();
				years.insert(year, *years.get(&year).unwrap_or(&0i32) + 1);
				sizes.insert(
					year,
					*sizes.get(&year).unwrap_or(&0usize) + entry.size as usize,
				);
				if !unique.contains_key(&year) {
					unique.insert(year, HashSet::new());
				}
				unique.get_mut(&year).unwrap().insert(&entry.ip);
			}
			let mut lines: Vec<String> = Vec::new();
			for (year, count) in years {
				lines.push(format!(
					"<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
					year,
					unique[&year].len(),
					count,
					format_percent(count as usize, entries.len()),
					human_readable_bytes(sizes[&year]),
					format_percent(sizes[&year], total_size)
				));
			}
			return lines.join("");
		}
		"yearly-avg-visitors" => {
			return get_average_visitors(entries, "%Y");
		}
		"yearly-avg-visits" => {
			return get_average_visits(entries, "%Y");
		}
		"yearly-avg-bandwidth" => {
			return get_average_bandwidth(entries, "%Y");
		}
		"monthly-rows" => {
			let month_names = vec![
				"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
			];
			let mut months: HashMap<i32, i32> = HashMap::new();
			let mut sizes: HashMap<i32, usize> = HashMap::new();
			let mut unique: HashMap<i32, HashSet<&str>> = HashMap::new();
			for entry in entries {
				let month = format_date(&entry.time, "%m").parse::<i32>().unwrap();
				months.insert(month, *months.get(&month).unwrap_or(&0i32) + 1);
				sizes.insert(
					month,
					*sizes.get(&month).unwrap_or(&0usize) + entry.size as usize,
				);
				if !unique.contains_key(&month) {
					unique.insert(month, HashSet::new());
				}
				unique.get_mut(&month).unwrap().insert(&entry.ip);
			}
			let mut lines: Vec<String> = Vec::new();
			for month in 1..13 {
				if !months.contains_key(&month) {
					months.insert(month, 0);
					sizes.insert(month, 0);
					unique.insert(month, HashSet::new());
				}
				lines.push(format!(
					"<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
					month_names[(month - 1) as usize],
					unique[&month].len(),
					months[&month],
					format_percent(months[&month] as usize, entries.len()),
					human_readable_bytes(sizes[&month]),
					format_percent(sizes[&month], total_size)
				));
			}
			return lines.join("");
		}
		"monthly-avg-visitors" => {
			return get_average_visitors(entries, "%m");
		}
		"monthly-avg-visits" => {
			return get_average_visits(entries, "%m");
		}
		"monthly-avg-bandwidth" => {
			return get_average_bandwidth(entries, "%m");
		}
		"day-of-month-rows" => {
			let mut days: HashMap<i32, i32> = HashMap::new();
			let mut sizes: HashMap<i32, usize> = HashMap::new();
			for entry in entries {
				let day = format_date(&entry.time, "%d").parse::<i32>().unwrap();
				days.insert(day, *days.get(&day).unwrap_or(&0i32) + 1);
				sizes.insert(
					day,
					*sizes.get(&day).unwrap_or(&0usize) + entry.size as usize,
				);
			}
			let mut lines: Vec<String> = Vec::new();
			for day in 1..32 {
				if !days.contains_key(&day) {
					days.insert(day, 0);
					sizes.insert(day, 0);
				}
				lines.push(format!(
					"<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
					day,
					days[&day],
					format_percent(days[&day] as usize, entries.len()),
					human_readable_bytes(sizes[&day]),
					format_percent(sizes[&day], total_size)
				));
			}
			return lines.join("");
		}
		"day-of-month-avg-visits" => {
			return get_average_visits(entries, "%d");
		}
		"day-of-month-avg-bandwidth" => {
			return get_average_bandwidth(entries, "%d");
		}
		"days-of-week-rows" => {
			let day_names = vec!["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
			let mut days: HashMap<i32, i32> = HashMap::new();
			let mut sizes: HashMap<i32, usize> = HashMap::new();
			for entry in entries {
				let day = format_date(&entry.time, "%w").parse::<i32>().unwrap();
				days.insert(day, *days.get(&day).unwrap_or(&0i32) + 1);
				sizes.insert(
					day,
					*sizes.get(&day).unwrap_or(&0usize) + entry.size as usize,
				);
			}
			let mut lines: Vec<String> = Vec::new();
			for day in 0..7 {
				if !days.contains_key(&day) {
					days.insert(day, 0);
					sizes.insert(day, 0);
				}
				lines.push(format!(
					"<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
					day_names[day as usize],
					days[&day],
					format_percent(days[&day] as usize, entries.len()),
					human_readable_bytes(sizes[&day]),
					format_percent(sizes[&day], total_size)
				));
			}
			return lines.join("");
		}
		"hourly-rows" => {
			let mut hours: HashMap<i32, i32> = HashMap::new();
			let mut sizes: HashMap<i32, usize> = HashMap::new();
			for entry in entries {
				let hour = format_date(&entry.time, "%H").parse::<i32>().unwrap();
				hours.insert(hour, *hours.get(&hour).unwrap_or(&0i32) + 1);
				sizes.insert(
					hour,
					*sizes.get(&hour).unwrap_or(&0usize) + entry.size as usize,
				);
			}
			let mut lines: Vec<String> = Vec::new();
			for hour in 0..24 {
				if !hours.contains_key(&hour) {
					hours.insert(hour, 0);
					sizes.insert(hour, 0);
				}
				let h: String;
				if hour == 0 || hour == 12 {
					h = String::from("12");
				} else if hour < 12 {
					h = hour.to_string();
				} else {
					h = (hour - 12).to_string();
				}
				lines.push(format!(
					"<tr><td>{} {}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
					format!("{:\u{00A0}>2}", h),
					(hour < 12).then(|| "AM").unwrap_or("PM"),
					hours[&hour],
					format_percent(hours[&hour] as usize, entries.len()),
					human_readable_bytes(sizes[&hour]),
					format_percent(sizes[&hour], total_size)
				));
			}
			return lines.join("");
		}
		"ip-rows" => {
			let mut unique: LinkedHashMap<String, i32> = LinkedHashMap::new();
			let mut bw: HashMap<String, usize> = HashMap::new();
			let mut dates: HashMap<String, Vec<DateTime<FixedOffset>>> = HashMap::new();
			for entry in entries {
				unique.insert(
					entry.ip.clone(),
					*unique.get(&entry.ip).unwrap_or(&0i32) + 1,
				);
				bw.insert(
					entry.ip.clone(),
					*bw.get(&entry.ip).unwrap_or(&0usize) + entry.size as usize,
				);
				if !dates.contains_key(&entry.ip) {
					let vec: Vec<DateTime<FixedOffset>> = Vec::new();
					dates.insert(entry.ip.clone(), vec);
				}
				dates.get_mut(&entry.ip).unwrap().push(entry.time);
			}
			unique = sort_map(unique);
			let mut lines: Vec<String> = Vec::new();
			for (ip, count) in unique {
				dates
					.get_mut(&ip)
					.unwrap()
					.sort_by_key(|k| k.timestamp_millis());
				lines.push(format!(
					"<tr><td>{}</td><td><a href=\"{}\">View</a></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
					ip,
					config["whois-tool"]
					.as_str()
					.unwrap()
					.replace("<address>", &ip),
					count,
					format_percent(count as usize, entries.len()),
					human_readable_bytes(bw[&ip]),
					format_percent(bw[&ip], total_size),
					format_date_config(&dates[&ip][dates[&ip].len() - 1], &config)
				));
			}
			return lines.join("");
		}
		"users-rows" => {
			let mut unique: LinkedHashMap<String, i32> = LinkedHashMap::new();
			let mut bw: HashMap<String, usize> = HashMap::new();
			let mut dates: HashMap<String, Vec<DateTime<FixedOffset>>> = HashMap::new();
			for entry in entries {
				unique.insert(
					entry.user.clone(),
					*unique.get(&entry.user).unwrap_or(&0i32) + 1,
				);
				bw.insert(
					entry.user.clone(),
					*bw.get(&entry.user).unwrap_or(&0usize) + entry.size as usize,
				);
				if !dates.contains_key(&entry.user) {
					let vec: Vec<DateTime<FixedOffset>> = Vec::new();
					dates.insert(entry.user.clone(), vec);
				}
				dates.get_mut(&entry.user).unwrap().push(entry.time);
			}
			unique = sort_map(unique);
			let mut lines: Vec<String> = Vec::new();
			for (user, count) in unique {
				dates
					.get_mut(&user)
					.unwrap()
					.sort_by_key(|k| k.timestamp_millis());
				lines.push(format!(
					"<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
					get_or_else(&user, "unauthenticated"),
					count,
					format_percent(count as usize, entries.len()),
					human_readable_bytes(bw[&user]),
					format_percent(bw[&user], total_size),
					format_date_config(&dates[&user][dates[&user].len() - 1], &config)
				));
			}
			return lines.join("");
		}
		"agents-rows" => {
			let mut unique_agents: LinkedHashMap<String, i32> = LinkedHashMap::new();
			let mut unique_visitors: HashMap<String, HashSet<&str>> = HashMap::new();
			let mut bw: HashMap<String, usize> = HashMap::new();
			let mut dates: HashMap<String, Vec<DateTime<FixedOffset>>> = HashMap::new();
			for entry in entries {
				unique_agents.insert(
					entry.agent.clone(),
					*unique_agents.get(&entry.agent).unwrap_or(&0i32) + 1,
				);
				if !unique_visitors.contains_key(&entry.agent) {
					unique_visitors.insert(entry.agent.clone(), HashSet::new());
				}
				unique_visitors
					.get_mut(&entry.agent)
					.unwrap()
					.insert(&entry.ip);
				bw.insert(
					entry.agent.clone(),
					*bw.get(&entry.agent).unwrap_or(&0usize) + entry.size as usize,
				);
				if !dates.contains_key(&entry.agent) {
					let vec: Vec<DateTime<FixedOffset>> = Vec::new();
					dates.insert(entry.agent.clone(), vec);
				}
				dates.get_mut(&entry.agent).unwrap().push(entry.time);
			}
			unique_agents = sort_map(unique_agents);
			let mut lines: Vec<String> = Vec::new();
			for (agent, count) in unique_agents {
				dates
					.get_mut(&agent)
					.unwrap()
					.sort_by_key(|k| k.timestamp_millis());
				let truncate = config["truncate-user-agent"].as_i64().unwrap() as usize;
				if truncate != 0 && agent.len() > truncate {
					let a = &get_or_none(&agent)[..truncate];
					let show_agent: String;
					match config["show-full-agent"]
						.as_str()
						.unwrap()
						.to_lowercase()
						.as_str()
					{
						"hover" => {
							show_agent = format!("<abbr title=\"{}\">{}...</abbr>", agent, a);
						}
						"click" => {
							show_agent = format!(
								"<abbr onclick='javascript:prompt(\"Full user agent:\", \"{}\");'
							title=\"Click to display full user agent\">{}...</abbr>",
								agent, a
							);
						}
						_ => {
							show_agent = format!("{}...", a);
						}
					}
					lines.push(format!(
						"<tr><td class=\"ss-user-agent\">{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
						&show_agent,
						unique_visitors.len(),
						count,
						format_percent(count as usize, entries.len()),
						human_readable_bytes(bw[&agent]),
						format_percent(bw[&agent], total_size),
						format_date_config(&dates[&agent][dates[&agent].len() - 1], config))
					);
				} else {
					lines.push(format!(
						"<tr><td class=\"ss-user-agent\">{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
						get_or_none(&agent),
						unique_visitors.len(),
						count,
						format_percent(count as usize, entries.len()),
						human_readable_bytes(bw[&agent]),
						format_percent(bw[&agent], total_size),
						format_date_config(&dates[&agent][dates[&agent].len() - 1], config))
					);
				}
			}
			return lines.join("");
		}
		"pages-rows" => {
			let mut unique: LinkedHashMap<String, i32> = LinkedHashMap::new();
			let mut bw: HashMap<String, usize> = HashMap::new();
			for entry in entries {
				unique.insert(
					entry.request.clone(),
					*unique.get(&entry.request).unwrap_or(&0i32) + 1,
				);
				bw.insert(
					entry.request.clone(),
					*bw.get(&entry.request).unwrap_or(&0usize) + entry.size as usize,
				);
			}
			unique = sort_map(unique);
			let mut lines: Vec<String> = Vec::new();
			for (request, count) in unique {
				let split: Vec<&str> = request.split(" ").collect();
				lines.push(format!(
					"<tr><td>{}</td><td class=\"ss-page-url\">{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
					get_or_none(&split[0]).substring(0, 10),
					(split.len() > 1).then(|| split[1]).unwrap_or("(none)"),
					(split.len() > 2).then(|| split[2]).unwrap_or("(none)"),
					count,
					format_percent(count as usize, entries.len()),
					human_readable_bytes(bw[&request]),
					format_percent(bw[&request], total_size),
					human_readable_bytes((bw[&request] / entries.len()) as usize)
				));
			}
			return lines.join("");
		}
		"referers-rows" => {
			let mut unique: LinkedHashMap<String, i32> = LinkedHashMap::new();
			let mut bw: HashMap<String, usize> = HashMap::new();
			for entry in entries {
				unique.insert(
					entry.referer.clone(),
					*unique.get(&entry.referer).unwrap_or(&0i32) + 1,
				);
				bw.insert(
					entry.referer.clone(),
					*bw.get(&entry.referer).unwrap_or(&0usize) + entry.size as usize,
				);
			}
			unique = sort_map(unique);
			let mut lines: Vec<String> = Vec::new();
			for (referer, count) in unique {
				lines.push(format!(
					"<tr><td class=\"ss-referer\">{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
					get_or_none(&referer),
					count,
					format_percent(count as usize, entries.len()),
					human_readable_bytes(bw[&referer]),
					format_percent(bw[&referer], total_size)
				));
			}
			return lines.join("");
		}
		"responses-rows" => {
			let mut unique: LinkedHashMap<String, i32> = LinkedHashMap::new();
			let mut bw: HashMap<String, usize> = HashMap::new();
			for entry in entries {
				unique.insert(
					entry.response.clone(),
					*unique.get(&entry.response).unwrap_or(&0i32) + 1,
				);
				bw.insert(
					entry.response.clone(),
					*bw.get(&entry.response).unwrap_or(&0usize) + entry.size as usize,
				);
			}
			unique = sort_map(unique);
			let mut lines: Vec<String> = Vec::new();
			for (response, count) in unique {
				lines.push(format!(
					"<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
					response,
					count,
					format_percent(count as usize, entries.len()),
					human_readable_bytes(bw[&response]),
					format_percent(bw[&response], total_size)
				));
			}
			return lines.join("");
		}
		"footer" => {
			return String::from(format!(
				"<span class=\"ss-footer\"><a href=\"{}\">SimpleStats</a> {} by <a href=\"{}\">{}</a></span>",
				env!("CARGO_PKG_REPOSITORY"),
				env!("CARGO_PKG_VERSION"),
				env!("CARGO_PKG_HOMEPAGE"),
				env!("CARGO_PKG_AUTHORS")
			));
		}
		_ => {
			return String::from("(INVALID KEY)");
		}
	}

	fn human_readable_bytes(bytes: usize) -> String {
		let mut b = bytes as f64;
		let mut magnitude: usize = 0;
		while b > 1000f64 {
			b /= 1000f64;
			magnitude += 1;
		}
		if magnitude == 0 {
			return String::from(format!("{:0} B", b));
		} else {
			return String::from(format!(
				"{:.2} {}B",
				b,
				['k', 'M', 'G', 'T', 'P', 'E', 'Z', 'Y'][magnitude - 1]
			));
		}
	}

	fn format_percent(part: usize, whole: usize) -> String {
		return format!("{:.2}%", ((part as f64) / (whole as f64)) * 100f64);
	}

	fn sort_map(map: LinkedHashMap<String, i32>) -> LinkedHashMap<String, i32> {
		let mut v: Vec<(&String, &i32)> = map.iter().collect();
		v.sort_by(|a, b| b.1.cmp(a.1));
		let mut m: LinkedHashMap<String, i32> = LinkedHashMap::new();
		for entry in v {
			m.insert(entry.0.to_string(), *entry.1);
		}
		return m;
	}

	fn get_or_none(key: &str) -> &str {
		match key {
			"-" => return "(none)",
			_ => return key,
		}
	}

	fn get_or_else(key: &str, other: &str) -> String {
		match key {
			"-" => return format!("({})", other),
			_ => return String::from(key),
		}
	}

	fn get_average_visitors(entries: &Vec<Entry>, date_format: &str) -> String {
		let mut unique: HashSet<&str> = HashSet::new();
		let mut keys: HashSet<i32> = HashSet::new();
		for entry in entries {
			let key = format_date(&entry.time, date_format)
				.parse::<i32>()
				.unwrap();
			keys.insert(key);
			unique.insert(&entry.ip);
		}
		return (unique.len() / keys.len()).to_string();
	}

	fn get_average_visits(entries: &Vec<Entry>, date_format: &str) -> String {
		let mut keys: HashSet<i32> = HashSet::new();
		for entry in entries {
			let key = format_date(&entry.time, date_format)
				.parse::<i32>()
				.unwrap();
			keys.insert(key);
		}
		return (entries.len() / keys.len()).to_string();
	}

	fn get_average_bandwidth(entries: &Vec<Entry>, date_format: &str) -> String {
		let mut keys: HashMap<i32, usize> = HashMap::new();
		for entry in entries {
			let key = format_date(&entry.time, date_format)
				.parse::<i32>()
				.unwrap();
			keys.insert(
				key,
				*keys.get(&key).unwrap_or(&0usize) + entry.size as usize,
			);
		}
		let mut sum: usize = 0;
		for (_key, size) in &keys {
			sum += size;
		}
		return human_readable_bytes((sum / keys.len()) as usize);
	}

	fn format_date(date: &DateTime<FixedOffset>, format: &str) -> String {
		return Local
			.from_local_datetime(&date.naive_local())
			.unwrap()
			.format(&format)
			.to_string();
	}

	fn format_date_config(date: &DateTime<FixedOffset>, config: &Yaml) -> String {
		return format_date(date, config["output-date-format"].as_str().unwrap());
	}
}
