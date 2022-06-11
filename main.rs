use chrono::DateTime;
use chrono::FixedOffset;
use chrono::Local;
use chrono::TimeZone;
use chrono::Utc;
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

	let mut debug_counter: i32 = 0;

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

		debug_counter += 1;
		if debug_counter > 3 {
			// XXX debug statement
			break;
		}
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
			return Local
				.from_utc_datetime(&dates[0].naive_local())
				.format(&config["output-date-format"].as_str().unwrap())
				.to_string();
		}
		"latest-visit" => {
			let mut dates: Vec<DateTime<FixedOffset>> = Vec::new();
			for entry in entries {
				dates.push(entry.time);
			}
			dates.sort_by_key(|k| k.timestamp_millis());
			return Local
				.from_utc_datetime(&dates[dates.len() - 1].naive_local())
				.format(&config["output-date-format"].as_str().unwrap())
				.to_string();
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
			let mut size = 0;
			for entry in entries {
				size += entry.size;
			}
			return human_readable_bytes(size);
		}
		"yearly-rows" => {
			return String::from("!!UNIMPLEMENTED!!");
		}
		"yearly-avg-visitors" => {
			return String::from("!!UNIMPLEMENTED!!");
		}
		"yearly-avg-visits" => {
			return String::from("!!UNIMPLEMENTED!!");
		}
		"yearly-avg-bandwidth" => {
			return String::from("!!UNIMPLEMENTED!!");
		}
		"monthly-rows" => {
			return String::from("!!UNIMPLEMENTED!!");
		}
		"monthly-avg-visitors" => {
			return String::from("!!UNIMPLEMENTED!!");
		}
		"monthly-avg-visits" => {
			return String::from("!!UNIMPLEMENTED!!");
		}
		"monthly-avg-bandwidth" => {
			return String::from("!!UNIMPLEMENTED!!");
		}
		"day-of-month-rows" => {
			return String::from("!!UNIMPLEMENTED!!");
		}
		"day-of-month-avg-visits" => {
			return String::from("!!UNIMPLEMENTED!!");
		}
		"day-of-month-avg-bandwidth" => {
			return String::from("!!UNIMPLEMENTED!!");
		}
		"days-of-week-rows" => {
			return String::from("!!UNIMPLEMENTED!!");
		}
		"hourly-rows" => {
			return String::from("!!UNIMPLEMENTED!!");
		}
		"ip-rows" => {
			return String::from("!!UNIMPLEMENTED!!");
		}
		"users-rows" => {
			return String::from("!!UNIMPLEMENTED!!");
		}
		"agents-rows" => {
			return String::from("!!UNIMPLEMENTED!!");
		}
		"pages-rows" => {
			return String::from("!!UNIMPLEMENTED!!");
		}
		"referers-rows" => {
			return String::from("!!UNIMPLEMENTED!!");
		}
		"responses-rows" => {
			return String::from("!!UNIMPLEMENTED!!");
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

	fn human_readable_bytes(bytes: i32) -> String {
		let mut b = f64::from(bytes);
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
}
