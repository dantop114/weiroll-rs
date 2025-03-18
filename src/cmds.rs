use crate::calls::FunctionCall;
use bitflags::bitflags;
use ethers::abi::{AbiEncode, Tokenizable};
use ethers::prelude::Bytes;
use slotmap::DefaultKey;
use std::fmt::Debug;
use std::hash::Hash;

bitflags! {
    #[derive(Debug, PartialEq, Clone, Copy)]
    #[repr(transparent)]
    pub struct CommandFlags: u8 {
        // Specifies that a call should be made using the DELEGATECALL opcode
        const DELEGATECALL = 0x00;
        // Specifies that a call should be made using the CALL opcode
        const CALL = 0x01;
        // Specifies that a call should be made using the STATICCALL opcode
        const STATICCALL = 0x02;
        // Specifies that a call should be made using the CALL opcode, and that the first argument will be the value to send
        const CALL_WITH_VALUE = 0x03;
        // Specifies that a call should be made using the CALL opcode, and that the first argument will be the value to send
        const CALL_WITH_VALUE_RETURN = 0x04;
        // A bitmask that selects calltype flags
        const CALLTYPE_MASK = 0x03;
        // Specifies that this is an extended command, with an additional command word for indices. Internal use only.
        const EXTENDED_COMMAND = 0x40;
        // Specifies that the return value of this call should be wrapped in a `bytes`. Internal use only.
        const TUPLE_RETURN = 0x80;
    }
}

pub const IDX_DYNAMIC_END: u8 = 0xFB;
pub const IDX_TUPLE_START: u8 = 0xFC;
pub const IDX_ARRAY_START: u8 = 0xFD;

pub const IDX_VARIABLE_LENGTH: u8 = 0x80;
pub const IDX_END_OF_ARGS: u8 = 0xFF;
pub const IDX_USE_STATE: u8 = 0xFE;

#[derive(Debug, PartialEq, Clone)]
pub enum CommandType {
    Call,
    RawCall,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Literal {
    dynamic: bool,
    bytes: Bytes,
}
impl Eq for Literal {}

impl<T: Tokenizable + AbiEncode + Clone> From<T> for Literal {
    fn from(token: T) -> Self {
        Literal {
            dynamic: token.clone().into_token().is_dynamic(),
            bytes: token.encode().into(),
        }
    }
}

impl<T: Tokenizable + AbiEncode + Clone> From<T> for Value {
    fn from(token: T) -> Self {
        Value::Literal(token.into())
    }
}

impl Literal {
    pub fn bytes(&self) -> Bytes {
        self.bytes.clone()
    }

    pub fn new(dynamic: bool, bytes: Bytes) -> Self {
        Literal { dynamic, bytes }
    }
}

impl Hash for Literal {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.bytes.hash(state)
    }
}

#[derive(Debug, Clone)]
pub enum Value {
    Literal(Literal),
    Return(ReturnValue),
    Array(Vec<Value>),
    Tuple(Vec<Value>),
    State(Vec<Bytes>),
}

impl From<ReturnValue> for Value {
    fn from(value: ReturnValue) -> Self {
        Self::Return(value)
    }
}

impl Value {
    pub fn is_dynamic_type(&self) -> bool {
        match self {
            Value::Tuple(values) => values.iter().any(|v| v.is_dynamic_type()),
            Value::Array(_) => true, // we return true because we only use this type for dynamic arrays
            Value::Literal(l) => l.dynamic,
            Value::Return(r) => r.dynamic,
            Value::State(_) => true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Command {
    pub(crate) call: FunctionCall,
    pub(crate) kind: CommandType,
}

#[derive(Clone, Debug)]
pub struct ReturnValue {
    pub(crate) dynamic: bool,
    pub(crate) command: DefaultKey,
}
