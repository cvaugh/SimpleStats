use std::fs;
use substring::Substring;

struct Element {
    value : String,
    start : usize,
    end : usize
}

fn main() {
    let access_log_path = String::from("log/access.log");
    read_log(access_log_path);
}

fn read_log(path: String) {
    println!("Reading file: {}", path);

    let contents = fs::read_to_string(path).expect("Failed to read file");

    let mut debug_counter : i32 = 0;
    for line in contents.split("\n") {
        if line.chars().count() == 0 {
            continue;
        }
        print!("line {}: ", debug_counter);
        parse_log_line(String::from(line), line.chars().collect());
        print!("\n");
        debug_counter += 1;
        if debug_counter > 10 { // XXX debug statement
            break;
        }
    }
}

fn parse_log_line(original : String, line: Vec<char>) {
    let mut ip = Element { value: String::new(), start: 0, end: usize::MAX };
    let mut user = Element { value: String::new(), start: usize::MAX, end: usize::MAX };
    let mut time = Element { value: String::new(), start: usize::MAX, end: usize::MAX };
    let mut request = Element { value: String::new(), start: usize::MAX, end: usize::MAX };
    let mut response = Element { value: String::new(), start: usize::MAX, end: usize::MAX };
    let mut size = Element { value: String::new(), start: usize::MAX, end: usize::MAX };
    let mut referer = Element { value: String::new(), start: usize::MAX, end: usize::MAX };
    let mut agent = Element { value: String::new(), start: usize::MAX, end: usize::MAX };
    let mut section : i32 = 0;
    let mut bracket_escape : bool = false;
    let mut quote_escape : bool = false;
    let mut ignore_next : bool = false;
    let mut first : bool = true;
    let mut i : usize = 0;
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

    ip.value = original.substring(ip.start, ip.end).to_string();
    user.value = original.substring(user.start, user.end).to_string();
    time.value = original.substring(time.start, time.end).to_string();
    request.value = original.substring(request.start, request.end).to_string();
    response.value = original.substring(response.start, response.end).to_string();
    size.value = original.substring(size.start, size.end).to_string();
    referer.value = original.substring(referer.start, referer.end).to_string();
    agent.value = original.substring(agent.start, agent.end).to_string();

    print!("ip: {}, user: {}, time: {}, request: {}, response: {}, size: {}, referer: {}, agent: {}",
        ip.value, user.value, time.value, request.value, response.value, size.value, referer.value, agent.value);
}
