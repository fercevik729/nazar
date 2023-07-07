macro_rules! assert_ok {
    ($expression: expr, $expected: expr) => {
        match $expression {
            Ok(value) => assert_eq!(value, $expected),
            Err(err) => panic!("Expected Ok({:?}), but got Err({:?})", $expected, err),
        }
    };
}

macro_rules! assert_err {
    ($expression: expr, $expected: expr) => {
        match $expression {
            Ok(value) => panic!("Expected Err({:?}), but got Ok({:?})", $expected, value),
            Err(err) => assert_eq!(format!("{}", err), $expected),
        }
    };
}

pub(crate) use assert_err;
pub(crate) use assert_ok;
