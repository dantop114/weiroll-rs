use alloy::dyn_abi::DynSolType;
use alloy::primitives::{Address, U256};

use crate::cmds::{CommandFlags, Value};

#[derive(Debug, Clone)]
pub struct FunctionCall {
    pub(crate) address: Address,
    pub(crate) selector: [u8; 4],
    pub(crate) flags: CommandFlags,
    pub(crate) value: Option<U256>,
    pub(crate) args: Vec<Value>,
    pub(crate) return_type: DynSolType,
}

impl FunctionCall {
    pub fn with_value(mut self, value: U256) -> Self {
        self.flags = (self.flags & !CommandFlags::CALLTYPE_MASK) | CommandFlags::CALL_WITH_VALUE;
        self.value = Some(value);
        self
    }

    pub fn raw_value(mut self) -> Self {
        self.flags |= CommandFlags::TUPLE_RETURN;
        self
    }

    pub fn static_call(mut self) -> Self {
        if (self.flags & CommandFlags::CALLTYPE_MASK) != CommandFlags::CALL {
            panic!("Only CALL operations can be made static");
        }
        self.flags |= CommandFlags::TUPLE_RETURN;
        self
    }
}
