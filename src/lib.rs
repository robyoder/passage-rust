pub struct Passage {
    app_id: String,
    api_key: Option<String>,
}

impl Passage {
    pub fn new(app_id: String, api_key: Option<String>) -> Self {
        Passage { app_id, api_key }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_passage() {
        let passage = Passage::new(String::from("test"), None);
        assert_eq!(passage.app_id, String::from("test"));
        assert_eq!(passage.api_key, None);
    }
}
