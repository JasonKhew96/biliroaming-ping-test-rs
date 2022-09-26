use std::collections::HashMap;
use std::env;
use std::error::Error;
use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::Deserialize;

const USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36";

const ANDROID_APPKEY: &str = "1d8b6e7d45233436";
const ANDROID_SECKEY: &str = "560c52ccd288fed045859ed18bffd973";

const BSTAR_A_APPKEY: &str = "7d089525d3611b1c";
const BSTAR_A_SECKEY: &str = "acd495b248ec528c2eed1e862d393126";

// const PLAYURL_WEB: &str = "pgc/player/web/playurl";
const PLAYURL_ANDROID: &str = "pgc/player/api/playurl";
const PLAYURL_BSTAR_A: &str = "intl/gateway/v2/ogv/playurl";

struct AreaEp(&'static str, i32);

const EP_LIST: &[&AreaEp] = &[
    &AreaEp("cn", 266323),
    &AreaEp("hk", 425578),
    &AreaEp("tw", 285951),
    &AreaEp("th", 377544),
];

// The output is wrapped in a Result to allow matching on errors
// Returns an Iterator to the Reader of the lines of the file.
fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where
    P: AsRef<Path>,
{
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}

fn get_server_list(filename: &str) -> Vec<String> {
    let mut server_list = Vec::new();
    if let Ok(lines) = read_lines(filename) {
        for line in lines {
            if let Ok(server) = line {
                if server.starts_with("#") || server.trim().is_empty() {
                    continue;
                }
                server_list.push(server);
            }
        }
    }
    server_list
}

fn queries_to_string(queries: &HashMap<String, String>) -> String {
    let mut sorted_queries = queries
        .keys()
        .map(|key| {
            let value = queries.get(key).unwrap();
            format!("{}={}", key, value)
        })
        .collect::<Vec<String>>();
    sorted_queries.sort_by(|a, b| a.cmp(b));
    sorted_queries.join("&")
}

fn generate_signature(queries: &HashMap<String, String>, appsec: &str) -> String {
    let mut queries_string = queries_to_string(&queries);
    queries_string.push_str(appsec);
    let signature = md5::compute(queries_string);
    format!("{:x}", signature)
}

fn sign_query(queries: &mut HashMap<String, String>, appkey: &str, appsec: &str) {
    queries.insert(String::from("appkey"), appkey.to_owned());
    queries.insert(
        String::from("ts"),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .to_string(),
    );
    let sign_string: String = generate_signature(queries, appsec);
    let sign: &str = sign_string.as_str();
    queries.insert(String::from("sign"), sign.to_owned());
}

fn build_queries(area: &str, ep: i32, access_key: &str) -> HashMap<String, String> {
    let mut queries: HashMap<String, String> = HashMap::new();
    queries.insert(String::from("access_key"), access_key.to_owned());
    queries.insert(String::from("ep_id"), ep.to_string());
    queries.insert(String::from("fnver"), String::from("0"));
    queries.insert(String::from("fnval"), String::from("4048"));
    queries.insert(String::from("platform"), String::from("android"));
    queries.insert(String::from("fourk"), String::from("1"));
    queries.insert(String::from("qn"), String::from("0"));
    if area == "th" {
        queries.insert(String::from("s_locale"), String::from("zh_SG"));
    } else {
        queries.insert(String::from("area"), area.to_owned());
    }
    return queries;
}

fn sign_queries(queries: &mut HashMap<String, String>, area: &str) {
    if area == "th" {
        sign_query(queries, BSTAR_A_APPKEY, BSTAR_A_SECKEY);
    } else {
        sign_query(queries, ANDROID_APPKEY, ANDROID_SECKEY);
    }
}

#[derive(Deserialize)]
struct BiliResp {
    code: i32,
}

fn testing(url: &str) -> Result<AreaResult, Box<dyn Error>> {
    let client = reqwest::blocking::ClientBuilder::new()
        .brotli(true)
        .gzip(true)
        .deflate(true)
        .timeout(Duration::from_secs(5))
        .user_agent(USER_AGENT)
        .build()
        .unwrap();

    let start_time = Instant::now();

    let body = client.get(url).send();
    let resp = match body {
        Ok(resp) => resp,
        Err(err) => {
            return Err(err.into());
        }
    };
    let status = resp.status();
    if status.is_success() {
        let resp_text = resp.text();
        let resp_text = match resp_text {
            Ok(resp_text) => resp_text,
            Err(err) => {
                return Err(err.into());
            }
        };
        let json_resp = serde_json::from_str::<BiliResp>(&resp_text);
        let code = match json_resp {
            Ok(resp) => resp.code,
            Err(err) => {
                if resp_text.contains("\"code\":0,") {
                    0
                } else {
                    return Err(err.into());
                }
            }
        };
        if code == 0 {
            return Ok(AreaResult {
                code,
                ms: start_time.elapsed().as_millis(),
            });
        } else {
            return Err(format!("code: {}", code).into());
        }
    }
    return Err(format!("status code: {}", status).into());
}

struct AreasResult {
    server: String,
    cn: Option<AreaResult>,
    hk: Option<AreaResult>,
    tw: Option<AreaResult>,
    th: Option<AreaResult>,
}

struct AreaResult {
    #[allow(dead_code)]
    code: i32,
    ms: u128,
}

fn main() {
    let access_key = env::var("ACCESS_KEY").unwrap();

    let server_list = get_server_list("server_list.txt");

    let mut results: Vec<AreasResult> = Vec::new();

    for server in server_list {
        let mut result = AreasResult {
            server: server.clone(),
            cn: None,
            hk: None,
            tw: None,
            th: None,
        };

        for ep_data in EP_LIST {
            let mut queries = build_queries(ep_data.0, ep_data.1, access_key.as_str());
            sign_queries(&mut queries, ep_data.0);
            let queries_string = queries_to_string(&queries);

            let url_prefix = if ep_data.0 == "th" {
                format!("https://{}/{}", server, PLAYURL_BSTAR_A)
            } else {
                format!("https://{}/{}", server, PLAYURL_ANDROID)
            };
            let url = format!("{}?{}", url_prefix, queries_string);

            match testing(&url) {
                Ok(area_result) => {
                    println!("{} ({}): {}ms", server, ep_data.0, area_result.ms);
                    match ep_data.0 {
                        "cn" => {
                            result.cn = Some(area_result);
                        }
                        "hk" => {
                            result.hk = Some(area_result);
                        }
                        "tw" => {
                            result.tw = Some(area_result);
                        }
                        "th" => {
                            result.th = Some(area_result);
                        }
                        _ => (),
                    }
                }
                Err(err) => {
                    println!("{} ({}): {}", server, ep_data.0, err);
                }
            }
            std::thread::sleep(Duration::from_millis(150));
        }
        results.push(result);
    }

    print!("\n   cn   |   hk   |   tw   |   th   | server\n");
    for result in results {
        match result.cn {
            Some(area_result) => {
                print!(" {:>4}ms ", area_result.ms);
            }
            None => {
                print!("        ");
            }
        }
        print!("|");
        match result.hk {
            Some(area_result) => {
                print!(" {:>4}ms ", area_result.ms);
            }
            None => {
                print!("        ");
            }
        }
        print!("|");
        match result.tw {
            Some(area_result) => {
                print!(" {:>4}ms ", area_result.ms);
            }
            None => {
                print!("        ");
            }
        }
        print!("|");
        match result.th {
            Some(area_result) => {
                print!(" {:>4}ms ", area_result.ms);
            }
            None => {
                print!("        ");
            }
        }
        print!("| {}\n", result.server);
    }
}
