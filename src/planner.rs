use crate::calls::FunctionCall;
use crate::cmds::{
    is_type_dynamic, Command, CommandFlags, CommandType, Literal, ReturnValue, Value,
    IDX_ARRAY_START, IDX_DYNAMIC_END, IDX_END_OF_ARGS, IDX_TUPLE_START, IDX_USE_STATE,
    IDX_VARIABLE_LENGTH,
};
use crate::error::WeirollError;

use bytes::BufMut;
use bytes::BytesMut;

use alloy::dyn_abi::DynSolType;
use alloy::primitives::{Address, Bytes, U256};

use slotmap::{DefaultKey, HopSlotMap};
use std::collections::{HashMap, HashSet};

type CommandKey = DefaultKey;

#[derive(Debug, Default, Clone)]
pub struct Planner {
    commands: HopSlotMap<CommandKey, Command>,
}

#[derive(Debug, Default)]
pub struct PlannerState {
    return_slot_map: HashMap<CommandKey, u8>,
    literal_slot_map: HashMap<Literal, u8>,
    free_slots: Vec<u8>,
    state_expirations: HashMap<CommandKey, Vec<u8>>,
    command_visibility: HashMap<CommandKey, CommandKey>,
    state: Vec<Bytes>,
}

impl Planner {
    pub fn call(
        &mut self,
        address: Address,
        command_flag: CommandFlags,
        selector: [u8; 4],
        args: Vec<Value>,
        return_type: DynSolType,
        value: Option<U256>,
    ) -> Result<ReturnValue, WeirollError> {
        let (dynamic, return_type) =
            if (command_flag & CommandFlags::TUPLE_RETURN) == CommandFlags::TUPLE_RETURN {
                (true, DynSolType::Bytes)
            } else {
                (is_type_dynamic(&return_type), return_type)
            };

        let call = FunctionCall {
            address,
            flags: command_flag,
            value,
            selector,
            args,
            return_type,
        };

        let command = self.commands.insert(Command::new(call, CommandType::Call));

        Ok(ReturnValue::new(command, dynamic))
    }

    pub fn raw_call(
        &mut self,
        address: Address,
        command_flag: CommandFlags,
        selector: [u8; 4],
        args: Vec<Value>,
        return_type: DynSolType,
        value: Option<U256>,
    ) -> Result<(), WeirollError> {
        let return_type = match &return_type {
            DynSolType::Array(inner_type) if **inner_type == DynSolType::Bytes => return_type,
            _ => return Err(WeirollError::InvalidReturnType),
        };

        let call = FunctionCall {
            address,
            flags: command_flag,
            value,
            selector,
            args,
            return_type,
        };

        self.commands
            .insert(Command::new(call, CommandType::RawCall));

        Ok(())
    }

    fn get_slots(
        arg: &Value,
        return_slot_map: &HashMap<CommandKey, u8>,
        literal_slot_map: &HashMap<Literal, u8>,
    ) -> Result<Vec<u8>, WeirollError> {
        let mut slots = vec![];

        match arg {
            Value::Array(values) | Value::Tuple(values) | Value::FixedArray(values) => {
                if matches!(arg, Value::Array(_)) {
                    slots.push(IDX_ARRAY_START);

                    let length = U256::from(values.len());

                    if let Some(slot) = literal_slot_map.get(&length.into()) {
                        slots.push(*slot);
                    } else {
                        return Err(WeirollError::MissingLiteralValue);
                    }
                }

                if matches!(arg, Value::Tuple(_)) && arg.is_dynamic() {
                    slots.push(IDX_TUPLE_START);
                }

                for value in values.iter() {
                    slots.extend(Self::get_slots(value, return_slot_map, literal_slot_map)?);
                }

                if matches!(arg, Value::Array(_))
                    || (matches!(arg, Value::Tuple(_)) && arg.is_dynamic())
                {
                    slots.push(IDX_DYNAMIC_END);
                }
            }
            Value::Literal(literal) => {
                if let Some(slot) = literal_slot_map.get(literal) {
                    let mut slot = *slot;

                    if arg.is_dynamic() {
                        slot |= IDX_VARIABLE_LENGTH;
                    }

                    slots.push(slot);
                } else {
                    return Err(WeirollError::MissingLiteralValue);
                }
            }
            Value::Return(ret) => {
                if let Some(slot) = return_slot_map.get(&ret.command()) {
                    let mut slot = *slot;

                    if arg.is_dynamic() {
                        slot |= IDX_VARIABLE_LENGTH;
                    }

                    slots.push(slot);
                } else {
                    return Err(WeirollError::MissingReturnSlot);
                }
            }
            Value::State(_) => {
                slots.push(IDX_USE_STATE | IDX_VARIABLE_LENGTH);
            }
        }

        Ok(slots)
    }

    fn build_command_args(
        &self,
        command: &Command,
        return_slot_map: &HashMap<CommandKey, u8>,
        literal_slot_map: &HashMap<Literal, u8>,
    ) -> Result<Vec<u8>, WeirollError> {
        let in_args = Vec::from_iter(command.call().args.iter());
        let mut extra_args: Vec<Value> = vec![];

        if command.call().flags & CommandFlags::CALLTYPE_MASK == CommandFlags::CALL_WITH_VALUE {
            if let Some(value) = command.call().value {
                extra_args.push(Value::Literal(value.into()));
            } else {
                return Err(WeirollError::MissingValue);
            }
        }

        let mut args = vec![];
        for arg in extra_args.iter().chain(in_args.into_iter()) {
            let slots = Self::get_slots(arg, return_slot_map, literal_slot_map)?;
            args.extend(slots);
        }

        Ok(args)
    }

    fn build_commands(&self, ps: &mut PlannerState) -> Result<Vec<Bytes>, WeirollError> {
        let mut encoded_commands = vec![];

        // Build commands, and add state entries as needed
        for (cmd_key, command) in &self.commands {
            let mut flags = command.call().flags;

            let mut args =
                self.build_command_args(command, &ps.return_slot_map, &ps.literal_slot_map)?;

            if args.len() > 6 {
                flags |= CommandFlags::EXTENDED_COMMAND;
            }

            if let Some(expr) = ps.state_expirations.get(&cmd_key) {
                ps.free_slots.extend(expr.iter().copied())
            };

            // Figure out where to put the return value
            let mut ret = IDX_END_OF_ARGS;

            if let Some(return_slot) = ps.return_slot_map.get(&cmd_key) {
                ret = *return_slot;
            } else if ps.command_visibility.contains_key(&cmd_key) {
                if matches!(command.kind(), CommandType::RawCall) {
                    return Err(WeirollError::InvalidReturnSlot);
                }

                ret = ps.state.len() as u8;

                if let Some(slot) = ps.free_slots.pop() {
                    ret = slot;
                }

                ps.return_slot_map.insert(cmd_key, ret);

                let expiry_command = ps.command_visibility.get(&cmd_key).unwrap();
                ps.state_expirations
                    .entry(*expiry_command)
                    .or_default()
                    .push(ret);

                if ret == ps.state.len() as u8 {
                    ps.state.push(Bytes::default());
                }

                if is_type_dynamic(&command.call().return_type) {
                    ret |= IDX_VARIABLE_LENGTH;
                }
            } else if matches!(command.kind(), CommandType::RawCall) {
                ret = IDX_USE_STATE;
            }

            if (flags & CommandFlags::EXTENDED_COMMAND) == CommandFlags::EXTENDED_COMMAND {
                let mut cmd = BytesMut::with_capacity(32);

                cmd.put(&command.call().selector[..]);
                cmd.put(&flags.bits().to_le_bytes()[..]);
                cmd.put(&[0u8; 6][..]);
                cmd.put_u8(ret);
                cmd.put(&command.call().address.0[..]);

                // push first command, indicating extended cmd
                encoded_commands.push(cmd.to_vec().into());

                // use the next command for the actual args
                args.push(IDX_END_OF_ARGS);
                args.resize(32, 0);

                encoded_commands.push(Bytes::from(args.to_vec()));
            } else {
                let mut cmd = BytesMut::with_capacity(32);

                args.push(IDX_END_OF_ARGS);
                args.resize(6, 0);

                cmd.put(&command.call().selector[..]);
                cmd.put(&flags.bits().to_le_bytes()[..]);
                cmd.put(&args[..]);
                cmd.put_u8(ret);
                cmd.put(&command.call().address.0[..]);

                encoded_commands.push(cmd.to_vec().into());
            }
        }

        Ok(encoded_commands)
    }

    fn set_visibility(
        arg: &Value,
        cmd_key: CommandKey,
        literal_visibility: &mut Vec<(Literal, CommandKey)>,
        command_visibility: &mut HashMap<CommandKey, CommandKey>,
        seen: &mut HashSet<CommandKey>,
    ) -> Result<(), WeirollError> {
        match arg {
            Value::Return(ret) => {
                if seen.contains(&ret.command()) {
                    command_visibility.insert(ret.command(), cmd_key);
                } else {
                    return Err(WeirollError::InvalidReturnSlot);
                }
            }
            Value::Literal(lit) => {
                // Remove old visibility (if exists)
                literal_visibility.retain(|(l, _)| *l != *lit);
                literal_visibility.push((lit.clone(), cmd_key));
            }
            Value::Array(values) | Value::Tuple(values) | Value::FixedArray(values) => {
                // For arrays, we need to track the length as a literal
                if let Value::Array(values) = arg {
                    let length_literal = U256::from(values.len()).into();
                    literal_visibility.retain(|(l, _)| *l != length_literal);
                    literal_visibility.push((length_literal, cmd_key));
                }

                // Recursively set visibility for all values in the collection
                for value in values {
                    Self::set_visibility(
                        value,
                        cmd_key,
                        literal_visibility,
                        command_visibility,
                        seen,
                    )?;
                }
            }
            Value::State(_) => {}
        }

        Ok(())
    }

    fn preplan(
        &self,
        literal_visibility: &mut Vec<(Literal, CommandKey)>,
        command_visibility: &mut HashMap<CommandKey, CommandKey>,
        seen: &mut HashSet<CommandKey>,
    ) -> Result<(), WeirollError> {
        for (cmd_key, command) in &self.commands {
            let in_args = &command.call().args;
            let mut extra_args = vec![];

            if command.call().flags & CommandFlags::CALLTYPE_MASK == CommandFlags::CALL_WITH_VALUE {
                if let Some(value) = command.call().value {
                    extra_args.push(value.into())
                } else {
                    return Err(WeirollError::MissingValue);
                }
            }

            for arg in extra_args.iter().chain(in_args.iter()) {
                Self::set_visibility(arg, cmd_key, literal_visibility, command_visibility, seen)?;
            }

            seen.insert(cmd_key);
        }

        Ok(())
    }

    pub fn plan(
        &self,
        reserved_slots: Vec<Value>,
    ) -> Result<(Vec<Bytes>, Vec<Bytes>), WeirollError> {
        // Tracks the last time a literal is used in the program
        let mut literal_visibility: Vec<(Literal, CommandKey)> = Default::default();

        // Tracks the last time a command's output is used in the program
        let mut command_visibility: HashMap<CommandKey, CommandKey> = HashMap::new();

        // Populate visibility maps
        self.preplan(
            &mut literal_visibility,
            &mut command_visibility,
            &mut HashSet::new(),
        )?;

        // Maps from commands to the slots that expire on execution (if any)
        let mut state_expirations: HashMap<CommandKey, Vec<u8>> = Default::default();

        // Tracks the state slot each literal is stored in
        let mut literal_slot_map: HashMap<Literal, u8> = Default::default();

        let mut state: Vec<Bytes> = Default::default();

        let mut return_slot_map: HashMap<CommandKey, u8> = Default::default();

        for (slot, value) in reserved_slots.iter().enumerate() {
            match value {
                Value::Literal(literal) => {
                    state.push(literal.bytes_cloned());
                    literal_slot_map.insert(literal.clone(), slot as u8);
                }
                Value::Return(ret) => {
                    state.push(Bytes::default());
                    return_slot_map.insert(ret.command(), slot as u8);
                }
                _ => {
                    return Err(WeirollError::InvalidReservedSlot);
                }
            }
        }

        // Prepopulate the state and state expirations with literals
        for (literal, last_command) in literal_visibility {
            if literal_slot_map.contains_key(&literal) {
                continue;
            }

            let slot = state.len();

            state.push(literal.bytes_cloned());

            state_expirations
                .entry(last_command)
                .or_default()
                .push(slot as u8);

            literal_slot_map.insert(literal, slot as u8);
        }

        let mut ps = PlannerState {
            return_slot_map,
            literal_slot_map,
            free_slots: Default::default(),
            state_expirations,
            command_visibility,
            state,
        };

        let encoded_commands = self.build_commands(&mut ps)?;

        Ok((encoded_commands, ps.state))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::str::FromStr;

    use alloy::primitives::{address, Address, FixedBytes, U256};
    use alloy::sol;
    use alloy::sol_types::SolCall;
    use alloy::sol_types::SolValue;
    use ExtendedCommandContract::extendedCommandCall;
    use FixedArrayContract::{fixedArrayBytesCall, fixedArrayUintCall};
    use Math::{addCall, sumCall};
    use StringUtils::{strcatCall, strlenCall};
    use TakesBytes::takesBytesCall;
    use TupleContract::tupleCall;

    sol! {
        #[allow(missing_docs)]
        contract SampleContract {
            function useState(bytes[] memory state) returns(bytes[] memory) {
                return state;
            }
        }
    }

    sol! {
        #[allow(missing_docs)]
        contract Math {
            function add(uint256 a, uint256 b) returns(uint256) {
                return a + b;
            }

            function sub(uint256 a, uint256 b) returns(uint256) {
                return a - b;
            }

            function sum(uint256[] memory values) returns(uint256) {
                uint256 total;
                for (uint256 i = 0; i < values.length; i++) {
                    total += values[i];
                }
                return total;
            }
        }
    }

    sol! {
        #[allow(missing_docs)]
        contract StringUtils {
            function strlen(string memory s) returns(uint256) {
                return bytes(s).length;
            }

            function strcat(string memory a, string memory b) returns(string memory) {
                return string.concat(a, b);
            }
        }
    }

    sol! {
        #[allow(missing_docs)]
        contract TupleContract {
            function tuple() returns(uint256, uint256, string memory) {
                return (1, 2, "Hello, world!");
            }
        }
    }

    sol! {
        #[allow(missing_docs)]
        contract TakesBytes {
            function takesBytes(bytes memory b) {
                b;
            }
        }
    }

    sol! {
        #[allow(missing_docs)]
        contract FixedArrayContract {
            function fixedArrayUint(uint256[3] memory a) {
                a;
            }

            function fixedArrayBytes(bytes[3] memory a) {
                a;
            }
        }
    }

    sol! {
        #[allow(missing_docs)]
        contract ExtendedCommandContract {
            function extendedCommand(
                uint256 a,
                uint256 b,
                bytes memory c,
                (uint256,bytes32,uint256[],bytes) memory t,
                string memory s
            ) {
                a;
                b;
                c;
                t;
                s;
            }
        }
    }

    fn addr() -> Address {
        address!("0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")
    }

    #[test]
    fn test_planner_add() {
        let mut planner = Planner::default();

        planner
            .call(
                addr(),
                CommandFlags::CALL,
                addCall::SELECTOR,
                vec![U256::from(1).into(), U256::from(2).into()],
                DynSolType::Uint(256),
                Some(U256::ZERO),
            )
            .expect("Could not add call");

        let (commands, state) = planner.plan(vec![]).expect("Could not plan");

        assert_eq!(commands.len(), 1);
        assert_eq!(
            commands[0],
            Bytes::from(vec![
                0x77, 0x16, 0x02, 0xf7, 0x01, 0x00, 0x01, 0xff, 0x00, 0x00, 0x00, 0xff, 0xee, 0xee,
                0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee,
                0xee, 0xee, 0xee, 0xee
            ])
        );

        assert_eq!(state.len(), 2);
        assert_eq!(state[0], U256::from(1).abi_encode());
        assert_eq!(state[1], U256::from(2).abi_encode());
    }

    #[test]
    fn test_planner_add_with_value() {
        let mut planner = Planner::default();
        let value = U256::from(1e18 as u128);

        planner
            .call(
                addr(),
                CommandFlags::CALL_WITH_VALUE,
                addCall::SELECTOR,
                vec![U256::from(1).into(), U256::from(2).into()],
                DynSolType::Uint(256),
                Some(value),
            )
            .expect("Could not add call");

        let (commands, state) = planner.plan(vec![]).expect("Could not plan");

        assert_eq!(commands.len(), 1);
        assert_eq!(
            commands[0],
            Bytes::from(vec![
                0x77, 0x16, 0x02, 0xf7, 0x03, 0x00, 0x01, 0x02, 0xff, 0x00, 0x00, 0xff, 0xee, 0xee,
                0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee,
                0xee, 0xee, 0xee, 0xee
            ])
        );
        assert_eq!(state.len(), 3);
        assert_eq!(state[0], value.abi_encode());
        assert_eq!(state[1], U256::from(1).abi_encode());
        assert_eq!(state[2], U256::from(2).abi_encode());
    }

    #[test]
    fn test_planner_deduplicates_literals() {
        let mut planner = Planner::default();

        let num = U256::from(1);

        planner
            .call(
                addr(),
                CommandFlags::CALL,
                addCall::SELECTOR,
                vec![num.into(), num.into()],
                DynSolType::Uint(256),
                Some(U256::ZERO),
            )
            .expect("Could not add call");

        let (commands, state) = planner.plan(vec![]).expect("Could not plan");

        assert_eq!(commands.len(), 1);
        assert_eq!(
            commands[0],
            Bytes::from(vec![
                0x77, 0x16, 0x02, 0xf7, 0x01, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 0xff, 0xee, 0xee,
                0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee,
                0xee, 0xee, 0xee, 0xee
            ])
        );

        assert_eq!(state.len(), 1);
        assert_eq!(state[0], num.abi_encode());
    }

    #[test]
    fn test_planner_return_values() {
        let mut planner = Planner::default();

        let ret = planner
            .call(
                addr(),
                CommandFlags::CALL,
                addCall::SELECTOR,
                vec![U256::from(1).into(), U256::from(2).into()],
                DynSolType::Uint(256),
                Some(U256::ZERO),
            )
            .expect("Could not add call");

        planner
            .call(
                addr(),
                CommandFlags::CALL,
                addCall::SELECTOR,
                vec![ret.into(), U256::from(3).into()],
                DynSolType::Uint(256),
                Some(U256::ZERO),
            )
            .expect("Could not add call with return val");

        let (commands, state) = planner.plan(vec![]).expect("Could not plan");
        assert_eq!(commands.len(), 2);
        assert_eq!(
            commands[0],
            Bytes::from(vec![
                0x77, 0x16, 0x02, 0xf7, 0x01, 0x00, 0x01, 0xff, 0x00, 0x00, 0x00, 0x01, 0xee, 0xee,
                0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee,
                0xee, 0xee, 0xee, 0xee
            ])
        );
        assert_eq!(
            commands[1],
            Bytes::from(vec![
                0x77, 0x16, 0x02, 0xf7, 0x01, 0x01, 0x02, 0xff, 0x00, 0x00, 0x00, 0xff, 0xee, 0xee,
                0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee,
                0xee, 0xee, 0xee, 0xee
            ])
        );
        assert_eq!(state.len(), 3);
        assert_eq!(state[0], U256::from(1).abi_encode());
        assert_eq!(state[1], U256::from(2).abi_encode());
        assert_eq!(state[2], U256::from(3).abi_encode());
    }

    #[test]
    fn test_planner_intermediate_state_slots() {
        // todo: how is this different from test_planner_return_values?
        let mut planner = Planner::default();
        let ret = planner
            .call(
                addr(),
                CommandFlags::CALL,
                addCall::SELECTOR,
                vec![U256::from(1).into(), U256::from(1).into()],
                DynSolType::Uint(256),
                Some(U256::ZERO),
            )
            .expect("Could not add call");
        planner
            .call(
                addr(),
                CommandFlags::CALL,
                addCall::SELECTOR,
                vec![U256::from(1).into(), ret.into()],
                DynSolType::Uint(256),
                Some(U256::ZERO),
            )
            .expect("Could not add call with return val");

        let (commands, state) = planner.plan(vec![]).expect("Could not plan");

        assert_eq!(commands.len(), 2);
        assert_eq!(
            commands[0],
            Bytes::from(vec![
                0x77, 0x16, 0x02, 0xf7, 0x01, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 0x01, 0xee, 0xee,
                0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee,
                0xee, 0xee, 0xee, 0xee
            ])
        );
        assert_eq!(
            commands[1],
            Bytes::from(vec![
                0x77, 0x16, 0x02, 0xf7, 0x01, 0x00, 0x01, 0xff, 0x00, 0x00, 0x00, 0xff, 0xee, 0xee,
                0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee,
                0xee, 0xee, 0xee, 0xee
            ])
        );
        assert_eq!(state.len(), 2);
        assert_eq!(state[0], U256::from(1).abi_encode());
        assert_eq!(state[1], Bytes::default());
    }

    #[test]
    fn test_planner_dynamic_arguments() {
        let mut planner = Planner::default();

        planner
            .call(
                addr(),
                CommandFlags::CALL,
                strlenCall::SELECTOR,
                vec![String::from("Hello, world!").into()],
                DynSolType::Uint(256),
                Some(U256::ZERO),
            )
            .expect("Could not add call");

        let (commands, state) = planner.plan(vec![]).expect("Could not plan");

        assert_eq!(commands.len(), 1);
        assert_eq!(
            commands[0],
            Bytes::from(vec![
                0x36, 0x7b, 0xbd, 0x78, 0x01, 0x80, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xee, 0xee,
                0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee,
                0xee, 0xee, 0xee, 0xee
            ])
        );

        assert_eq!(state.len(), 1);
        assert_eq!(
            state[0],
            "Hello, world!".to_string().abi_encode()[32..].to_vec()
        );
    }

    #[test]
    fn test_planner_dynamic_return_values() {
        let mut planner = Planner::default();
        let _ret = planner
            .call(
                addr(),
                CommandFlags::CALL,
                strcatCall::SELECTOR,
                vec![
                    String::from("Hello, ").into(),
                    String::from("world!").into(),
                ],
                DynSolType::String,
                Some(U256::ZERO),
            )
            .expect("Could not add call");
        let (commands, state) = planner.plan(vec![]).expect("Could not plan");
        assert_eq!(commands.len(), 1);
        assert_eq!(
            commands[0],
            Bytes::from(vec![
                0xd8, 0x24, 0xcc, 0xf3, 0x01, 0x80, 0x81, 0xff, 0x00, 0x00, 0x00, 0xff, 0xee, 0xee,
                0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee,
                0xee, 0xee, 0xee, 0xee
            ])
        );
        assert_eq!(state.len(), 2);
        assert_eq!(state[0], "Hello, ".to_string().abi_encode()[32..].to_vec());
        assert_eq!(state[1], "world!".to_string().abi_encode()[32..].to_vec());
    }

    #[test]
    fn test_planner_dynamic_return_values_with_dynamic_arguments() {
        let mut planner = Planner::default();

        let ret = planner
            .call(
                addr(),
                CommandFlags::CALL,
                strcatCall::SELECTOR,
                vec![
                    String::from("Hello, ").into(),
                    String::from("world!").into(),
                ],
                DynSolType::String,
                Some(U256::ZERO),
            )
            .expect("Could not add call");

        planner
            .call(
                addr(),
                CommandFlags::CALL,
                strlenCall::SELECTOR,
                vec![ret.into()],
                DynSolType::Uint(256),
                Some(U256::ZERO),
            )
            .expect("Could not add call with return val");

        let (commands, state) = planner.plan(vec![]).expect("Could not plan");
        assert_eq!(commands.len(), 2);
        assert_eq!(
            commands[0],
            Bytes::from(vec![
                0xd8, 0x24, 0xcc, 0xf3, 0x01, 0x80, 0x81, 0xff, 0x00, 0x00, 0x00, 0x81, 0xee, 0xee,
                0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee,
                0xee, 0xee, 0xee, 0xee
            ])
        );
        assert_eq!(
            commands[1],
            Bytes::from(vec![
                0x36, 0x7b, 0xbd, 0x78, 0x01, 0x81, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xee, 0xee,
                0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee,
                0xee, 0xee, 0xee, 0xee
            ])
        );
        assert_eq!(state.len(), 2);
        assert_eq!(state[0], "Hello, ".to_string().abi_encode()[32..].to_vec());
        assert_eq!(state[1], "world!".to_string().abi_encode()[32..].to_vec());
    }

    #[test]
    fn test_planner_with_array() {
        let mut planner = Planner::default();
        let ret1 = planner
            .call(
                addr(),
                CommandFlags::CALL,
                addCall::SELECTOR,
                vec![U256::from(1).into(), U256::from(2).into()],
                DynSolType::Uint(256),
                Some(U256::ZERO),
            )
            .expect("Could not add call");

        let ret2 = planner
            .call(
                addr(),
                CommandFlags::CALL,
                addCall::SELECTOR,
                vec![U256::from(3).into(), U256::from(4).into()],
                DynSolType::Uint(256),
                Some(U256::ZERO),
            )
            .expect("Could not add call");

        planner
            .call(
                addr(),
                CommandFlags::CALL,
                sumCall::SELECTOR,
                vec![Value::Array(vec![
                    ret1.into(),
                    ret2.into(),
                    U256::from(5).into(),
                ])],
                DynSolType::Uint(256),
                Some(U256::ZERO),
            )
            .expect("Could not add call");

        let (commands, state) = planner.plan(vec![]).expect("Could not plan");

        assert_eq!(commands.len(), 3);
        assert_eq!(state.len(), 5);

        assert_eq!(state[0], U256::from(1).abi_encode());
        assert_eq!(state[1], U256::from(2).abi_encode());
        assert_eq!(state[2], U256::from(4).abi_encode());
        assert_eq!(state[3], U256::from(3).abi_encode());
        assert_eq!(state[4], U256::from(5).abi_encode());

        assert_eq!(
            commands[0],
            Bytes::from(vec![
                0x77, 0x16, 0x02, 0xf7, 0x01, 0x00, 0x01, 0xff, 0x00, 0x00, 0x00, 0x01, 0xee, 0xee,
                0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee,
                0xee, 0xee, 0xee, 0xee
            ])
        );

        assert_eq!(
            commands[1],
            Bytes::from(vec![
                0x77, 0x16, 0x02, 0xf7, 0x01, 0x03, 0x02, 0xff, 0x00, 0x00, 0x00, 0x02, 0xee, 0xee,
                0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee,
                0xee, 0xee, 0xee, 0xee
            ])
        );

        assert_eq!(
            commands[2],
            Bytes::from(vec![
                0x01, 0x94, 0xdb, 0x8e, 0x01, 0xfd, 0x03, 0x01, 0x02, 0x04, 0xfb, 0xff, 0xee, 0xee,
                0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee,
                0xee, 0xee, 0xee, 0xee
            ])
        );
    }

    #[test]
    fn test_planner_with_fixed_array() {
        let mut planner = Planner::default();

        planner
            .call(
                addr(),
                CommandFlags::CALL,
                fixedArrayUintCall::SELECTOR,
                vec![Value::FixedArray(vec![
                    U256::from(1).into(),
                    U256::from(2).into(),
                    U256::from(3).into(),
                ])],
                DynSolType::Bool,
                Some(U256::ZERO),
            )
            .expect("Could not add call");

        planner
            .call(
                addr(),
                CommandFlags::CALL,
                fixedArrayBytesCall::SELECTOR,
                vec![Value::FixedArray(vec![
                    Bytes::from_str("0xdeadbeef").unwrap().into(),
                    Bytes::from_str("0xdeadbeef").unwrap().into(),
                    Bytes::from_str("0xdeadbeef").unwrap().into(),
                ])],
                DynSolType::Bool,
                Some(U256::ZERO),
            )
            .expect("Could not add call");

        let (commands, state) = planner.plan(vec![]).expect("Could not plan");

        assert_eq!(commands.len(), 2);
        assert_eq!(state.len(), 4);

        assert_eq!(state[0], U256::from(1).abi_encode());
        assert_eq!(state[1], U256::from(2).abi_encode());
        assert_eq!(state[2], U256::from(3).abi_encode());
        assert_eq!(
            state[3],
            Bytes::from(vec![
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x04, // length of bytes padded to 32 bytes
                0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00
            ])
        );

        assert_eq!(
            commands[0],
            Bytes::from(vec![
                0x18, 0x9d, 0xd6, 0x92, 0x01, 0x00, 0x01, 0x02, 0xff, 0x00, 0x00, 0xff, 0xee, 0xee,
                0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee,
                0xee, 0xee, 0xee, 0xee
            ])
        );

        assert_eq!(
            commands[1],
            Bytes::from(vec![
                0xc4, 0x3e, 0xc4, 0x64, 0x01, 0x83, 0x83, 0x83, 0xff, 0x00, 0x00, 0xff, 0xee, 0xee,
                0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee,
                0xee, 0xee, 0xee, 0xee
            ])
        );
    }

    #[test]
    fn test_planner_with_reserved_slots() {
        let mut planner = Planner::default();

        let reserved_slot_end: Value = U256::MAX.into();
        let mut reserved_slots: Vec<Value> = vec![];

        let ret1 = planner
            .call(
                addr(),
                CommandFlags::CALL,
                addCall::SELECTOR,
                vec![U256::from(1).into(), U256::from(2).into()],
                DynSolType::Uint(256),
                Some(U256::ZERO),
            )
            .expect("Could not add call");

        reserved_slots.push(ret1.into());
        reserved_slots.push(reserved_slot_end);

        let (commands, state) = planner.plan(reserved_slots).expect("Could not plan");

        assert_eq!(commands.len(), 1);
        assert_eq!(state.len(), 4);

        assert_eq!(
            commands[0],
            Bytes::from(vec![
                0x77, 0x16, 0x02, 0xf7, 0x01, 0x02, 0x03, 0xff, 0x00, 0x00, 0x00, 0x00, 0xee, 0xee,
                0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee,
                0xee, 0xee, 0xee, 0xee
            ])
        );

        assert_eq!(state[0], Bytes::default());
        assert_eq!(state[1], U256::MAX.abi_encode());
        assert_eq!(state[2], U256::from(1).abi_encode());
        assert_eq!(state[3], U256::from(2).abi_encode());
    }

    #[test]
    fn test_planner_with_tuple_return() {
        let mut planner = Planner::default();

        let ret = planner
            .call(
                addr(),
                CommandFlags::CALL | CommandFlags::TUPLE_RETURN,
                tupleCall::SELECTOR,
                vec![],
                DynSolType::Tuple(vec![
                    DynSolType::Uint(256),
                    DynSolType::Uint(256),
                    DynSolType::String,
                ]),
                Some(U256::ZERO),
            )
            .expect("Could not add call");

        planner
            .call(
                addr(),
                CommandFlags::CALL,
                takesBytesCall::SELECTOR,
                vec![ret.into()],
                DynSolType::Bool,
                Some(U256::ZERO),
            )
            .expect("Could not add call");

        let (commands, state) = planner.plan(vec![]).expect("Could not plan");

        assert_eq!(commands.len(), 2);
        assert_eq!(state.len(), 1);

        assert_eq!(
            commands[0],
            Bytes::from(vec![
                0x31, 0x75, 0xaa, 0xe2, 0x81, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0xee, 0xee,
                0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee,
                0xee, 0xee, 0xee, 0xee
            ])
        );

        assert_eq!(
            commands[1],
            Bytes::from(vec![
                0xd2, 0x58, 0x34, 0x6c, 0x01, 0x80, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xee, 0xee,
                0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee,
                0xee, 0xee, 0xee, 0xee
            ])
        );

        assert_eq!(state[0], Bytes::default());
    }

    #[test]
    fn test_planner_extended_command() {
        let mut planner = Planner::default();

        planner
            .call(
                addr(),
                CommandFlags::CALL,
                extendedCommandCall::SELECTOR,
                vec![
                    U256::from(1).into(),
                    U256::from(2).into(),
                    Bytes::from_str("0xdeadbeef").unwrap().into(),
                    Value::Tuple(vec![
                        U256::from(3).into(),
                        FixedBytes::<32>::from(&[0; 32]).into(),
                        Value::Array(vec![U256::from(4).into(), U256::from(5).into()]),
                        Bytes::from_str("0xdeadbeef").unwrap().into(),
                    ]),
                    String::from("Hello, weiroll!").into(),
                ],
                DynSolType::Bool,
                Some(U256::ZERO),
            )
            .expect("Could not add call");

        let (commands, state) = planner.plan(vec![]).expect("Could not plan");

        // Let's explain what is going on with the state here:
        // We will deduplicate the literals in the state, which are:
        //  - 0xdeadbeef
        //  - the uint256(2), which is one of the arguments and the size of the array
        // So in total we should have 8 items in the state:
        // - state[0] = 1 (argument of the call)
        // - state[1] = 3 (argument of the call)
        // - state[2] = 0 (bytes32, argument of the call)
        // - state[3] = 2 (argument of the call AND size of the array)
        // - state[4] = 4 (first element of the array)
        // - state[5] = 5 (second element of the array)
        // - state[6] = 0xdeadbeef (bytes, argument of the call, deduplicated)
        // - state[7] = "Hello, weiroll!" (string, argument of the call)
        assert_eq!(state.len(), 8);
        assert_eq!(state[0], U256::from(1).abi_encode());
        assert_eq!(state[1], U256::from(3).abi_encode());
        assert_eq!(state[2], U256::from(0).abi_encode());
        assert_eq!(state[3], U256::from(2).abi_encode());
        assert_eq!(state[4], U256::from(4).abi_encode());
        assert_eq!(state[5], U256::from(5).abi_encode());

        assert_eq!(
            state[6],
            Bytes::from_str("0xdeadbeef").unwrap().abi_encode()[32..].to_vec()
        );

        assert_eq!(
            state[7],
            "Hello, weiroll!".to_string().abi_encode()[32..].to_vec()
        );

        // Now that we know what the state looks like, let's explain what will happen with the commands:
        // First command will have more than 6 arguments, so we need to have an extended command.
        // So first command will be:
        // |030adae7| -> selector of `ExtendedCommandContract.extendedCommand`
        // |41| -> CALL | EXTENDED_COMMAND flag
        // |000000000000| -> no further arguments, they will all be in the second command
        // |ff| -> no return value
        // |eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee| -> address of the contract
        // Second command will be:
        // |00| -> first argument of the call (uint256)
        // |03| -> second argument of the call (uint256)
        // |86| -> third argument of the call (the dynamic bytes)
        // |fc| -> start of the tuple
        // |01| -> first element of the tuple (uint256)
        // |02| -> second element of the tuple (bytes32)
        // |fd| -> start of the array
        // |03| -> size of the array (uint256)
        // |04| -> first element of the array (uint256)
        // |05| -> second element of the array (uint256)
        // |fb| -> end of the array
        // |86| -> bytes, element of the tuple
        // |fb| -> end of the tuple
        // |87| -> string, last argument of the call
        // |ff| -> end of the call
        // |0000000000000000000000000000000000| -> padding

        assert_eq!(commands.len(), 2);

        assert_eq!(
            commands[0],
            Bytes::from(vec![
                0x03, 0x0a, 0xda, 0xe7, 0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xee, 0xee,
                0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee,
                0xee, 0xee, 0xee, 0xee
            ])
        );

        assert_eq!(
            commands[1],
            Bytes::from(vec![
                0x00, 0x03, 0x86, 0xfc, 0x01, 0x02, 0xfd, 0x03, 0x04, 0x05, 0xfb, 0x86, 0xfb, 0x87,
                0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00
            ])
        );
    }
}
