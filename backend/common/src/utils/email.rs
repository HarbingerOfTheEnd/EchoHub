use regex::Regex;

pub trait IsValidEmail {
    fn is_valid_email(&self) -> bool;
}

impl IsValidEmail for String {
    fn is_valid_email(&self) -> bool {
        let email_regex = Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$").unwrap();

        email_regex.is_match(self)
    }
}

impl IsValidEmail for &str {
    fn is_valid_email(&self) -> bool {
        let email_regex = Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$").unwrap();

        email_regex.is_match(self)
    }
}
