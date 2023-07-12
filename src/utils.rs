mod test_macros {
    use std::collections::HashMap;

    #[cfg(test)]
    #[macro_export]
    macro_rules! assert_ok {
        ($expression: expr, $expected: expr) => {
            match $expression {
                Ok(value) => assert_eq!(value, $expected),
                Err(err) => panic!("Expected Ok({:?}), but got Err({:?})", $expected, err),
            }
        };
    }

    #[cfg(test)]
    #[macro_export]
    macro_rules! assert_err {
        ($expression: expr, $expected: expr) => {
            match $expression {
                Ok(value) => panic!("Expected Err({:?}), but got Ok({:?})", $expected, value),
                Err(err) => assert_eq!(format!("{}", err), $expected),
            }
        };
    }

    #[macro_export]
    macro_rules! hashmap {
        ($($key:expr => $value:expr),*) => {
            {
                let mut map = HashMap::new();
                $(map.insert($key, $value);)*
                map
            }
        };
    }
}
