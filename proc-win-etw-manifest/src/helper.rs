pub(crate) fn make_function_name(value: &mut String) {
    while let Some(i) = value.find(char::is_uppercase) {
        let x = &mut value[i..=i];
        x.make_ascii_lowercase();
        if i == 0 {
            continue;
        }
        if value[i - 1..].starts_with('_') {
            continue;
        }
        value.insert(i, '_');
    }
    while let Some(i) = value.find(' ') {
        value.remove(i);
    }
    while let Some(i) = value.find('.') {
        value.remove(i);
    }
    while let Some(i) = value.find(':') {
        value.remove(i);
    }
    while let Some(i) = value.find('/') {
        value.remove(i);
    }
    while let Some(i) = value.find('(') {
        value.remove(i);
    }
    while let Some(i) = value.find(')') {
        value.remove(i);
    }
}

#[cfg(test)]
mod test {
    #[test]
    fn test_make_function_name() {
        let mut name = "somethingThatsNotConvention".to_string();
        super::make_function_name(&mut name);
        assert_eq!(name, "something_thats_not_convention");

        let mut name = "StartsWithCapital".to_string();
        super::make_function_name(&mut name);
        assert_eq!(name, "starts_with_capital");

        let mut name = "already_has_Underscores".to_string();
        super::make_function_name(&mut name);
        assert_eq!(name, "already_has_underscores");

        let mut name = "has.Dot".to_string();
        super::make_function_name(&mut name);
        assert_eq!(name, "has_dot");

        let mut name = "has Space".to_string();
        super::make_function_name(&mut name);
        assert_eq!(name, "has_space");
    }
}
