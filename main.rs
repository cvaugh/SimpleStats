use chrono::DateTime;
use chrono::FixedOffset;
use chrono::Local;
use chrono::TimeZone;
use linked_hash_map::LinkedHashMap;
use std::collections::HashMap;
use std::collections::HashSet;
use std::fs;
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
	let config_path = String::from("simplestats.yml"); // TODO: store config in ~/.config

	let config = &YamlLoader::load_from_str(
		&fs::read_to_string(config_path).expect("Failed to read simplestats.yml"),
	)
	.unwrap()[0];

	// let access_log_path = config.get("input", "access-log-path").unwrap();
	let access_log_path = String::from("log/access.log"); // XXX debugging

	read_log(access_log_path, config);
}

fn read_log(path: String, config: &Yaml) {
	let contents = fs::read_to_string(path).expect("Failed to read file");

	let mut entries = Vec::new();

	for line in contents.split("\n") {
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
	let template_path_config = &config["template"];
	let template_path: &str;
	if template_path_config.is_null() {
		template_path = "template.html";
	} else {
		template_path = template_path_config.as_str().unwrap();
	}
	let mut template = fs::read_to_string(template_path).expect("Failed to read file");
	let replacements = &config["template-replacements"].as_hash().unwrap();

	for (key, value) in replacements.into_iter() {
		template = template.replace(
			&format!("{{{{{}}}}}", value.as_str().unwrap()),
			get_output(key.as_str().unwrap(), entries, &config).as_str(),
		);
	}

	// let output = &config["output-file"].as_str().unwrap();
	let output = "stats.html"; // debugging

	let result = fs::write(output, template);

	if result.is_err() {
		eprintln!(
			"Failed to write output to {}: {}",
			output,
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
			let mut unique: HashMap<i32, i32> = HashMap::new();
			for entry in entries {
				let year = format_date(&entry.time, "%Y").parse::<i32>().unwrap();
				let mut count = 0;
				let mut size: usize = 0;
				let mut u: HashSet<&str> = HashSet::new();
				for e in entries {
					if year == format_date(&e.time, "%Y").parse::<i32>().unwrap() {
						count += 1;
						size += e.size as usize;
						u.insert(&e.ip);
					}
				}
				years.insert(year, count);
				sizes.insert(year, size);
				unique.insert(year, u.len() as i32);
			}
			let mut lines: Vec<String> = Vec::new();
			for (year, count) in years {
				lines.push(format!(
					"<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
					year,
					unique[&year],
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
			let mut unique: HashMap<i32, i32> = HashMap::new();
			for entry in entries {
				let month = format_date(&entry.time, "%m").parse::<i32>().unwrap();
				let mut count = 0;
				let mut size: usize = 0;
				let mut u: HashSet<&str> = HashSet::new();
				for e in entries {
					if month == format_date(&e.time, "%m").parse::<i32>().unwrap() {
						count += 1;
						size += e.size as usize;
						u.insert(&e.ip);
					}
				}
				months.insert(month, count);
				sizes.insert(month, size);
				unique.insert(month, u.len() as i32);
			}
			let mut lines: Vec<String> = Vec::new();
			for month in 1..13 {
				if !months.contains_key(&month) {
					months.insert(month, 0);
					sizes.insert(month, 0);
					unique.insert(month, 0);
				}
				lines.push(format!(
					"<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
					month_names[(month - 1) as usize],
					unique[&month],
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
				let mut count = 0;
				let mut size: usize = 0;
				for e in entries {
					if day == format_date(&e.time, "%d").parse::<i32>().unwrap() {
						count += 1;
						size += e.size as usize;
					}
				}
				days.insert(day, count);
				sizes.insert(day, size);
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
				let mut count = 0;
				let mut size: usize = 0;
				for e in entries {
					if day == format_date(&e.time, "%w").parse::<i32>().unwrap() {
						count += 1;
						size += e.size as usize;
					}
				}
				days.insert(day, count);
				sizes.insert(day, size);
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
				let mut count = 0;
				let mut size: usize = 0;
				for e in entries {
					if hour == format_date(&e.time, "%H").parse::<i32>().unwrap() {
						count += 1;
						size += e.size as usize;
					}
				}
				hours.insert(hour, count);
				sizes.insert(hour, size);
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
			for entry in entries {
				if !unique.contains_key(&entry.ip) {
					let mut count: i32 = 0;
					for e in entries {
						if e.ip.eq(&entry.ip) {
							count += 1;
						}
					}
					unique.insert(entry.ip.clone(), count);
				}
			}
			unique = sort_map(unique);
			let mut lines: Vec<String> = Vec::new();
			for (ip, count) in unique {
				let mut bw = 0usize;
				for entry in entries {
					if entry.ip.eq(&ip) {
						bw += entry.size as usize;
					}
				}
				let mut dates: Vec<DateTime<FixedOffset>> = Vec::new();
				for entry in entries {
					if entry.ip.eq(&ip) {
						dates.push(entry.time);
					}
				}
				dates.sort_by_key(|k| k.timestamp_millis());
				lines.push(format!(
					"<tr><td>{}</td><td><a href=\"{}\">View</a></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
					ip,
					config["whois-tool"]
					.as_str()
					.unwrap()
					.replace("<address>", &ip),
					count,
					format_percent(count as usize, entries.len()),
					human_readable_bytes(bw),
					format_percent(bw, total_size),
					format_date_config(&dates[dates.len() - 1], &config)
				));
			}
			return lines.join("");
		}
		"users-rows" => {
			let mut unique: LinkedHashMap<String, i32> = LinkedHashMap::new();
			for entry in entries {
				if !unique.contains_key(&entry.user) {
					let mut count: i32 = 0;
					for e in entries {
						if e.user.eq(&entry.user) {
							count += 1;
						}
					}
					unique.insert(entry.user.clone(), count);
				}
			}
			unique = sort_map(unique);
			let mut lines: Vec<String> = Vec::new();
			for (user, count) in unique {
				let mut bw = 0usize;
				for entry in entries {
					if entry.user.eq(&user) {
						bw += entry.size as usize;
					}
				}
				let mut dates: Vec<DateTime<FixedOffset>> = Vec::new();
				for entry in entries {
					if entry.user.eq(&user) {
						dates.push(entry.time);
					}
				}
				dates.sort_by_key(|k| k.timestamp_millis());
				lines.push(format!(
					"<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
					get_or_else(&user, "unauthenticated"),
					count,
					format_percent(count as usize, entries.len()),
					human_readable_bytes(bw),
					format_percent(bw, total_size),
					format_date_config(&dates[dates.len() - 1], &config)
				));
			}
			return lines.join("");
		}
		"agents-rows" => {
			let mut unique_agents: LinkedHashMap<String, i32> = LinkedHashMap::new();
			for entry in entries {
				if !unique_agents.contains_key(&entry.agent) {
					let mut count: i32 = 0;
					for e in entries {
						if e.agent.eq(&entry.agent) {
							count += 1;
						}
					}
					unique_agents.insert(entry.agent.clone(), count);
				}
			}
			unique_agents = sort_map(unique_agents);
			let mut lines: Vec<String> = Vec::new();
			for (agent, count) in unique_agents {
				let mut unique_visitors: HashSet<&str> = HashSet::new();
				for entry in entries {
					if entry.agent.eq(&agent) {
						unique_visitors.insert(&entry.ip);
					}
				}
				let mut bw = 0usize;
				for entry in entries {
					if entry.agent.eq(&agent) {
						bw += entry.size as usize;
					}
				}
				let mut dates: Vec<DateTime<FixedOffset>> = Vec::new();
				for entry in entries {
					if entry.agent.eq(&agent) {
						dates.push(entry.time);
					}
				}
				dates.sort_by_key(|k| k.timestamp_millis());
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
						human_readable_bytes(bw),
						format_percent(bw, total_size),
						format_date_config(&dates[dates.len() - 1], config))
					);
				} else {
					lines.push(format!(
						"<tr><td class=\"ss-user-agent\">{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
						get_or_none(&agent),
						unique_visitors.len(),
						count,
						format_percent(count as usize, entries.len()),
						human_readable_bytes(bw),
						format_percent(bw, total_size),
						format_date_config(&dates[dates.len() - 1], config))
					);
				}
			}
			return lines.join("");
		}
		"pages-rows" => {
			let mut unique: LinkedHashMap<String, i32> = LinkedHashMap::new();
			for entry in entries {
				if !unique.contains_key(&entry.request) {
					let mut count: i32 = 0;
					for e in entries {
						if e.request.eq(&entry.request) {
							count += 1;
						}
					}
					unique.insert(entry.request.clone(), count);
				}
			}
			unique = sort_map(unique);
			let mut lines: Vec<String> = Vec::new();
			for (request, count) in unique {
				let mut bw = 0usize;
				for entry in entries {
					if entry.request.eq(&request) {
						bw += entry.size as usize;
					}
				}
				let split: Vec<&str> = request.split(" ").collect();
				lines.push(format!(
					"<tr><td>{}</td><td class=\"ss-page-url\">{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
					get_or_none(&split[0]),
					(split.len() > 1).then(|| split[1]).unwrap_or("(none)"),
					(split.len() > 2).then(|| split[2]).unwrap_or("(none)"),
					count,
					format_percent(count as usize, entries.len()),
					human_readable_bytes(bw),
					format_percent(bw, total_size),
					human_readable_bytes((bw / entries.len()) as usize)
				));
			}
			return lines.join("");
		}
		"referers-rows" => {
			let mut unique: LinkedHashMap<String, i32> = LinkedHashMap::new();
			for entry in entries {
				if !unique.contains_key(&entry.referer) {
					let mut count: i32 = 0;
					for e in entries {
						if e.referer.eq(&entry.referer) {
							count += 1;
						}
					}
					unique.insert(entry.referer.clone(), count);
				}
			}
			unique = sort_map(unique);
			let mut lines: Vec<String> = Vec::new();
			for (referer, count) in unique {
				let mut bw = 0usize;
				for entry in entries {
					if entry.referer.eq(&referer) {
						bw += entry.size as usize;
					}
				}
				lines.push(format!(
					"<tr><td class=\"ss-referer\">{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
					get_or_none(&referer),
					count,
					format_percent(count as usize, entries.len()),
					human_readable_bytes(bw),
					format_percent(bw, total_size)
				));
			}
			return lines.join("");
		}
		"responses-rows" => {
			let mut unique: LinkedHashMap<String, i32> = LinkedHashMap::new();
			for entry in entries {
				if !unique.contains_key(&entry.response) {
					let mut count: i32 = 0;
					for e in entries {
						if e.response.eq(&entry.response) {
							count += 1;
						}
					}
					unique.insert(entry.response.clone(), count);
				}
			}
			unique = sort_map(unique);
			let mut lines: Vec<String> = Vec::new();
			for (response, count) in unique {
				let mut bw = 0usize;
				for entry in entries {
					if entry.response.eq(&response) {
						bw += entry.size as usize;
					}
				}
				lines.push(format!(
					"<tr><td><abbr title=\"{}\">{}</abbr></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
					"!!UNIMPLEMENTED!!", response, count, format_percent(count as usize, entries.len()), human_readable_bytes(bw), format_percent(bw, total_size)
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
			let mut size: usize = 0;
			for e in entries {
				if key == format_date(&e.time, date_format).parse::<i32>().unwrap() {
					size += e.size as usize;
				}
			}
			keys.insert(key, size);
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
