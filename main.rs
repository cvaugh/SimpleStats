use chrono::DateTime;
use chrono::FixedOffset;
use chrono::Local;
use chrono::TimeZone;
use linked_hash_map::LinkedHashMap;
use std::collections::HashMap;
use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::process;
use substring::Substring;
use yaml_rust::Yaml;
use yaml_rust::YamlLoader;

struct Element {
	start: usize,
	end: usize,
}

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

	let access_log_path =
		shellexpand::tilde(config["access-log-path"].as_str().unwrap()).to_string();

	read_log(&access_log_path, config);
}

fn read_log(path: &str, config: &Yaml) {
	let contents = fs::read_to_string(path);
	if contents.is_err() {
		eprintln!("error: Access log not found: {}", &path);
		process::exit(1);
	}

	let mut entries = Vec::new();

	for line in contents.unwrap().split("\n") {
		if line.chars().count() == 0 {
			continue;
		}
		entries.push(parse_log_line(
			String::from(line),
			line.chars().collect(),
			config,
		));
	}
	write_output(&entries, config);
}

fn parse_log_line(original: String, line: Vec<char>, config: &Yaml) -> Entry {
	let mut ip = Element {
		start: 0,
		end: usize::MAX,
	};
	let mut user = Element {
		start: usize::MAX,
		end: usize::MAX,
	};
	let mut time = Element {
		start: usize::MAX,
		end: usize::MAX,
	};
	let mut request = Element {
		start: usize::MAX,
		end: usize::MAX,
	};
	let mut response = Element {
		start: usize::MAX,
		end: usize::MAX,
	};
	let mut size = Element {
		start: usize::MAX,
		end: usize::MAX,
	};
	let mut referer = Element {
		start: usize::MAX,
		end: usize::MAX,
	};
	let mut agent = Element {
		start: usize::MAX,
		end: usize::MAX,
	};
	let mut section: i32 = 0;
	let mut bracket_escape: bool = false;
	let mut quote_escape: bool = false;
	let mut ignore_next: bool = false;
	let mut first: bool = true;
	let mut i: usize = 0;
	loop {
		if first {
			first = false;
		} else {
			i += 1;
		}

		if i >= line.len() {
			break;
		}
		if bracket_escape {
			if line[i] == ']' {
				bracket_escape = false;
			} else {
				continue;
			}
		}
		if quote_escape {
			if line[i] == '"' {
				if line[i - 1] == '\\' {
					continue;
				} else {
					quote_escape = false;
				}
			} else {
				continue;
			}
		}
		if line[i] == ' ' {
			if ignore_next {
				ignore_next = false;
				continue;
			}
			if section == 0 {
				ip.end = i;
				user.start = i + 3;
				i += 2;
				section += 1;
				continue;
			}
			if section == 1 {
				user.end = i;
				time.start = i + 2;
				bracket_escape = true;
				section += 1;
				continue;
			}
			if section == 2 {
				time.end = i - 1;
				request.start = i + 2;
				quote_escape = true;
				i += 1;
				section += 1;
				continue;
			}
			if section == 3 {
				request.end = i - 1;
				response.start = i + 1;
				section += 1;
				continue;
			}
			if section == 4 {
				response.end = i;
				size.start = i + 1;
				section += 1;
				continue;
			}
			if section == 5 {
				size.end = i;
				referer.start = i + 2;
				quote_escape = true;
				i += 1;
				section += 1;
				continue;
			}
			if section == 6 {
				referer.end = i - 1;
				agent.start = i + 2;
				quote_escape = true;
				i += 1;
				section += 1;
				continue;
			}
		}
	}
	agent.end = i - 1;

	let entry = Entry {
		ip: original.substring(ip.start, ip.end).to_string(),
		user: original.substring(user.start, user.end).to_string(),
		time: DateTime::parse_from_str(
			original.substring(time.start, time.end),
			&config["input-date-format"].as_str().unwrap(),
		)
		.unwrap(),
		request: original.substring(request.start, request.end).to_string(),
		response: original.substring(response.start, response.end).to_string(),
		size: original
			.substring(size.start, size.end)
			.to_string()
			.parse::<i32>()
			.unwrap(),
		referer: original.substring(referer.start, referer.end).to_string(),
		agent: original.substring(agent.start, agent.end).to_string(),
	};

	return entry;
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
					get_or_none(&split[0]),
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
			.from_utc_datetime(&date.naive_local())
			.format(&format)
			.to_string();
	}

	fn format_date_config(date: &DateTime<FixedOffset>, config: &Yaml) -> String {
		return format_date(date, config["output-date-format"].as_str().unwrap());
	}
}
