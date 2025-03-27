use crate::calls::FunctionCall;

use bitflags::bitflags;

use alloy::dyn_abi::DynSolType;
use alloy::primitives::Bytes;
use alloy::sol_types::SolValue;

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

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum CommandType {
    Call,
    RawCall,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Literal {
    value: Bytes,
    dynamic: bool,
}

impl Literal {
    pub fn new(value: Bytes, dynamic: bool) -> Self {
        Self { value, dynamic }
    }

    pub fn dynamic(&self) -> bool {
        self.dynamic
    }

    pub fn bytes(&self) -> &Bytes {
        &self.value
    }

    pub fn bytes_cloned(&self) -> Bytes {
        self.value.clone()
    }
}

impl<T: SolValue> From<T> for Literal {
    fn from(token: T) -> Self {
        let value_type = DynSolType::parse(token.sol_name()).unwrap();
        let dynamic = is_type_dynamic(&value_type);

        // if the type is dynamic, we need to remove the starting/length prefix
        // because it will be handled by the weiroll virtual machine
        let mut bytes = token.abi_encode();
        if dynamic {
            bytes = bytes[32..].to_vec();
        }

        Self::new(bytes.into(), dynamic)
    }
}

impl<T: SolValue> From<T> for Value {
    fn from(token: T) -> Self {
        Self::Literal(token.into())
    }
}

impl Hash for Literal {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.value.hash(state);
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

pub fn is_type_dynamic(ty: &DynSolType) -> bool {
    match ty {
        DynSolType::Bytes | DynSolType::String | DynSolType::Array(_) => true,
        DynSolType::FixedArray(ty, _) => is_type_dynamic(ty),
        DynSolType::Tuple(types) => types.iter().any(is_type_dynamic),
        DynSolType::CustomStruct { tuple, .. } => tuple.iter().any(is_type_dynamic),
        _ => false,
    }
}

impl From<ReturnValue> for Value {
    fn from(value: ReturnValue) -> Self {
        Self::Return(value)
    }
}

impl Value {
    pub fn is_dynamic(&self) -> bool {
        match self {
            Value::Tuple(values) => values.iter().any(|v| v.is_dynamic()),
            Value::Array(_) => true,
            Value::Literal(l) => l.dynamic(),
            Value::Return(r) => r.dynamic(),
            Value::State(_) => true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Command {
    call: FunctionCall,
    kind: CommandType,
}

impl Command {
    pub fn new(call: FunctionCall, kind: CommandType) -> Self {
        Self { call, kind }
    }

    pub fn call(&self) -> &FunctionCall {
        &self.call
    }

    pub fn kind(&self) -> &CommandType {
        &self.kind
    }
}

#[derive(Clone, Debug)]
pub struct ReturnValue {
    dynamic: bool,
    command: DefaultKey,
}

impl ReturnValue {
    pub fn new(command: DefaultKey, dynamic: bool) -> Self {
        Self { dynamic, command }
    }

    pub fn command(&self) -> DefaultKey {
        self.command
    }

    pub fn dynamic(&self) -> bool {
        self.dynamic
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::str::FromStr;

    use alloy::primitives::U256;

    #[test]
    fn test_literal_from_u256_sol_value() {
        let value = U256::from(1);
        let encoded_value = Bytes::from(vec![
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01, // value padded to 32 bytes
        ]);

        let literal: Literal = value.into();

        assert!(!literal.dynamic());
        assert_eq!(literal.bytes_cloned(), encoded_value);
    }

    #[test]
    fn test_literal_from_bytes_sol_value() {
        let value = Bytes::from_str("0x1234567890abcdef").unwrap();

        let encoded_value = Bytes::from(vec![
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x08, // length padded to 32 bytes
            0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, // value padded to 32 bytes
        ]);

        let literal: Literal = value.clone().into();

        assert!(literal.dynamic());
        assert_eq!(literal.bytes_cloned(), encoded_value);
    }
}
