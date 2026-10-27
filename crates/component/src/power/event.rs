use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct Type(pub u8);

pub const SUSPEND: Type = Type(0);
pub const RESUME: Type = Type(1);
pub const RESUMEAUTOMATIC: Type = Type(2);

impl fmt::Display for Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match *self {
            SUSPEND => "SUSPEND",
            RESUME => "RESUME",
            RESUMEAUTOMATIC => "RESUMEAUTOMATIC",
            _ => "",
        })
    }
}
