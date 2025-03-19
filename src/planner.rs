use crate::calls::FunctionCall;
use crate::cmds::{
    Command, CommandFlags, CommandType, Literal, ReturnValue, Value, IDX_ARRAY_START,
    IDX_DYNAMIC_END, IDX_END_OF_ARGS, IDX_TUPLE_START, IDX_USE_STATE, IDX_VARIABLE_LENGTH,
};
use crate::error::WeirollError;

use bytes::BufMut;
use bytes::BytesMut;
use ethers::abi::ParamType;
use ethers::prelude::*;
use slotmap::{DefaultKey, HopSlotMap};
use std::collections::{HashMap, HashSet};

type CommandKey = DefaultKey;

#[derive(Debug, Default, Clone)]
pub struct Planner {
    commands: HopSlotMap<CommandKey, Command>,
}

#[derive(Debug, Default)]
pub struct PlannerState {
    return_slot_map: HashMap<CommandKey, U256>,
    literal_slot_map: HashMap<Literal, U256>,
    free_slots: Vec<U256>,
    state_expirations: HashMap<CommandKey, Vec<U256>>,
    command_visibility: HashMap<CommandKey, CommandKey>,
    state: Vec<Bytes>,
}

fn u256_bytes(u: U256) -> Bytes {
    let mut bytes = [0u8; 32];
    u.to_little_endian(&mut bytes);
    bytes.into()
}

fn concat_bytes(items: &[Bytes]) -> Bytes {
    let mut result = Vec::<u8>::new();
    for item in items {
        result.extend_from_slice(&item.0)
    }
    result.into()
}

fn pad_array<T>(array: Vec<T>, len: usize, value: T) -> Vec<T>
where
    T: Clone,
{
    let mut out = array;
    out.resize(len, value);
    out
}

impl Planner {
    pub fn call(
        &mut self,
        address: Address,
        command_flag: CommandFlags,
        selector: [u8; 4],
        args: Vec<Value>,
        return_type: ParamType,
        value: Option<U256>,
    ) -> Result<ReturnValue, WeirollError> {
        let (dynamic, return_type) =
            if (command_flag & CommandFlags::TUPLE_RETURN) == CommandFlags::TUPLE_RETURN {
                (true, ParamType::Bytes)
            } else {
                (return_type.is_dynamic(), return_type)
            };

        let call = FunctionCall {
            address,
            flags: command_flag,
            value,
            selector,
            args,
            return_type,
        };

        let command = self.commands.insert(Command {
            call,
            kind: CommandType::Call,
        });

        Ok(ReturnValue { command, dynamic })
    }

    fn get_slots(
        arg: &Value,
        return_slot_map: &HashMap<CommandKey, U256>,
        literal_slot_map: &HashMap<Literal, U256>,
    ) -> Result<Vec<U256>, WeirollError> {
        let mut slots = vec![];

        match arg {
            Value::Array(values) | Value::Tuple(values) => {
                if matches!(arg, Value::Array(_)) {
                    slots.push(U256::from(IDX_ARRAY_START));

                    let length = U256::from(values.len());

                    if let Some(slot) = literal_slot_map.get(&length.into()) {
                        slots.push(*slot);
                    } else {
                        return Err(WeirollError::MissingLiteralValue);
                    }
                }

                if matches!(arg, Value::Tuple(_)) && arg.is_dynamic_type() {
                    slots.push(U256::from(IDX_TUPLE_START));
                }

                for value in values.iter() {
                    slots.extend(Self::get_slots(value, return_slot_map, literal_slot_map)?);
                }

                if matches!(arg, Value::Array(_))
                    || (matches!(arg, Value::Tuple(_)) && arg.is_dynamic_type())
                {
                    slots.push(U256::from(IDX_DYNAMIC_END));
                }
            }
            Value::Literal(literal) => {
                if let Some(slot) = literal_slot_map.get(literal) {
                    let mut slot = *slot;

                    if arg.is_dynamic_type() {
                        slot |= U256::from(IDX_VARIABLE_LENGTH);
                    }

                    slots.push(slot);
                } else {
                    return Err(WeirollError::MissingLiteralValue);
                }
            }
            Value::Return(ret) => {
                if let Some(slot) = return_slot_map.get(&ret.command) {
                    let mut slot = *slot;

                    if arg.is_dynamic_type() {
                        slot |= U256::from(IDX_VARIABLE_LENGTH);
                    }

                    slots.push(slot);
                } else {
                    return Err(WeirollError::MissingReturnSlot);
                }
            }
            Value::State(_) => {
                slots.push(U256::from(IDX_USE_STATE) | U256::from(IDX_VARIABLE_LENGTH));
            }
        }

        Ok(slots)
    }

    fn build_command_args(
        &self,
        command: &Command,
        return_slot_map: &HashMap<CommandKey, U256>,
        literal_slot_map: &HashMap<Literal, U256>,
    ) -> Result<Vec<U256>, WeirollError> {
        let in_args = Vec::from_iter(command.call.args.iter());
        let mut extra_args: Vec<Value> = vec![];

        if command.call.flags & CommandFlags::CALLTYPE_MASK == CommandFlags::CALL_WITH_VALUE {
            if let Some(value) = command.call.value {
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
            let mut flags = command.call.flags;

            let mut args =
                self.build_command_args(command, &ps.return_slot_map, &ps.literal_slot_map)?;

            if args.len() > 6 {
                flags |= CommandFlags::EXTENDED_COMMAND;
            }

            if let Some(expr) = ps.state_expirations.get(&cmd_key) {
                ps.free_slots.extend(expr.iter().copied())
            };

            // Figure out where to put the return value
            let mut ret = U256::from(IDX_END_OF_ARGS);

            if let Some(return_slot) = ps.return_slot_map.get(&cmd_key) {
                println!("return slot: {:?}", return_slot);
                ret = *return_slot;
            } else if ps.command_visibility.contains_key(&cmd_key) {
                if matches!(command.kind, CommandType::RawCall) {
                    return Err(WeirollError::InvalidReturnSlot);
                }

                ret = U256::from(ps.state.len());
                if let Some(slot) = ps.free_slots.pop() {
                    ret = slot;
                }

                ps.return_slot_map.insert(cmd_key, ret);

                let expiry_command = ps.command_visibility.get(&cmd_key).unwrap();
                ps.state_expirations
                    .entry(*expiry_command)
                    .or_default()
                    .push(ret);

                if ret == U256::from(ps.state.len()) {
                    ps.state.push(Bytes::default());
                }

                if command.call.return_type.is_dynamic() {
                    ret |= U256::from(IDX_VARIABLE_LENGTH);
                }
            } else if matches!(command.kind, CommandType::RawCall) {
                // todo: what's this?
                // if command.call.fragment.outputs.len() == 1 {}
                ret = U256::from(IDX_USE_STATE);
            }

            if (flags & CommandFlags::EXTENDED_COMMAND) == CommandFlags::EXTENDED_COMMAND {
                let mut cmd = BytesMut::with_capacity(32);

                cmd.put(&command.call.selector[..]);
                cmd.put(&flags.bits().to_le_bytes()[..]);
                cmd.put(&[0u8; 6][..]);
                cmd.put_u8(ret.as_u128() as u8);
                cmd.put(&command.call.address.to_fixed_bytes()[..]);

                // push first command, indicating extended cmd
                encoded_commands.push(cmd.to_vec().into());

                // use the next command for the actual args
                args.resize(32, U256::from(IDX_END_OF_ARGS));
                encoded_commands.push(Bytes::from(
                    args.iter().map(|a| a.as_u128() as u8).collect::<Vec<_>>(),
                ));
            } else {
                // Standard command
                let mut encoded = vec![
                    command.call.selector.into(),
                    flags.bits().to_le_bytes().to_vec().into(),
                ];

                encoded.extend(
                    pad_array(args.clone(), 6, U256::from(IDX_END_OF_ARGS))
                        .iter()
                        .map(|o| u256_bytes(*o)[0..1].to_vec().into()),
                );

                encoded.push(u256_bytes(ret)[0..1].to_vec().into());
                encoded.push(command.call.address.to_fixed_bytes().into());
                encoded_commands.push(concat_bytes(&encoded));
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
                if seen.contains(&ret.command) {
                    command_visibility.insert(ret.command, cmd_key);
                } else {
                    return Err(WeirollError::InvalidReturnSlot);
                }
            }
            Value::Literal(lit) => {
                // Remove old visibility (if exists)
                literal_visibility.retain(|(l, _)| *l != *lit);
                literal_visibility.push((lit.clone(), cmd_key));
            }
            Value::Array(values) | Value::Tuple(values) => {
                // If it's a tuple we need to check if the tuple has a dynamic type in it.
                if matches!(arg, Value::Array(_)) {
                    let length_literal = U256::from(values.len()).into();
                    // Remove old visibility (if exists)
                    literal_visibility.retain(|(l, _)| *l != length_literal);
                    literal_visibility.push((length_literal, cmd_key));
                }

                for value in values.iter() {
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
            let in_args = &command.call.args;
            let mut extra_args = vec![];

            if command.call.flags & CommandFlags::CALLTYPE_MASK == CommandFlags::CALL_WITH_VALUE {
                if let Some(value) = command.call.value {
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

        //dbg!(&literal_visibility, &command_visibility);

        // Maps from commands to the slots that expire on execution (if any)
        let mut state_expirations: HashMap<CommandKey, Vec<U256>> = Default::default();

        // Tracks the state slot each literal is stored in
        let mut literal_slot_map: HashMap<Literal, U256> = Default::default();

        let mut state: Vec<Bytes> = Default::default();

        let mut return_slot_map: HashMap<CommandKey, U256> = Default::default();

        for (slot, value) in reserved_slots.iter().enumerate() {
            match value {
                Value::Literal(literal) => {
                    state.push(literal.bytes());
                    literal_slot_map.insert(literal.clone(), slot.into());
                }
                Value::Return(ret) => {
                    state.push(Bytes::default());
                    return_slot_map.insert(ret.command, slot.into());
                }
                _ => {
                    return Err(WeirollError::InvalidReservedSlot);
                }
            }
        }

        // Prepopulate the state and state expirations with literals
        for (literal, last_command) in literal_visibility {
            if literal_slot_map.contains_key(&literal) {
                println!("literal already exists: {:?}", literal);
                continue;
            }

            let slot = state.len();
            state.push(literal.bytes());
            state_expirations
                .entry(last_command)
                .or_default()
                .push(slot.into());
            literal_slot_map.insert(literal, slot.into());
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

        dbg!(&encoded_commands);

        // dbg!(&state);

        Ok((encoded_commands, ps.state))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethers::abi::AbiEncode;

    use std::str::FromStr;

    use crate::bindings::{
        math::{AddCall, SumCall},
        strings::{StrcatCall, StrlenCall},
    };

    abigen!(
        SampleContract,
        r#"[
            function useState(bytes[] state) returns(bytes[])
        ]"#,
    );

    fn addr() -> Address {
        "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
            .parse()
            .unwrap()
    }

    #[test]
    fn test_planner_add() {
        let mut planner = Planner::default();
        planner
            .call(
                addr(),
                CommandFlags::CALL,
                AddCall::selector(),
                vec![U256::from(1).into(), U256::from(2).into()],
                ParamType::Uint(256),
                Some(U256::zero()),
            )
            .expect("can add call");
        let (commands, state) = planner.plan(vec![]).expect("plan");

        assert_eq!(commands.len(), 1);
        assert_eq!(
            commands[0],
            "0x771602f7010001ffffffffffeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
                .parse::<Bytes>()
                .unwrap()
        );

        assert_eq!(state.len(), 2);
        assert_eq!(state[0], U256::from(1).encode());
        assert_eq!(state[1], U256::from(2).encode());
    }

    #[test]
    fn test_planner_add_with_value() {
        let mut planner = Planner::default();
        let value = U256::from(10_000_000_000_000_000_000_000u128);
        planner
            .call(
                addr(),
                CommandFlags::CALL_WITH_VALUE,
                AddCall::selector(),
                vec![U256::from(1).into(), U256::from(2).into()],
                ParamType::Uint(256),
                Some(value),
            )
            .expect("can add call");
        let (commands, state) = planner.plan(vec![]).expect("plan");

        println!("{:?}", commands);
        println!("{:?}", state);

        assert_eq!(commands.len(), 1);
        assert_eq!(
            commands[0],
            "0x771602f703000102ffffffffeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
                .parse::<Bytes>()
                .unwrap()
        );
        assert_eq!(state.len(), 3);
        assert_eq!(state[0], value.encode());
        assert_eq!(state[1], U256::from(1).encode());
        assert_eq!(state[2], U256::from(2).encode());
    }

    #[test]
    fn test_planner_add_with_value_return() {
        let mut planner = Planner::default();
        let value = U256::from(10_000_000_000_000_000_000_000u128);
        planner
            .call(
                addr(),
                CommandFlags::CALL_WITH_VALUE,
                AddCall::selector(),
                vec![U256::from(1).into(), U256::from(2).into()],
                ParamType::Uint(256),
                Some(value),
            )
            .expect("can add call");
        let (commands, state) = planner.plan(vec![]).expect("plan");

        println!("{:?}", commands);
        println!("{:?}", state);

        assert_eq!(commands.len(), 1);
        assert_eq!(
            commands[0],
            "0x771602f7030001ffffffffffeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
                .parse::<Bytes>()
                .unwrap()
        );
        assert_eq!(state.len(), 2);
        assert_eq!(state[0], U256::from(1).encode());
        assert_eq!(state[1], U256::from(2).encode());
    }

    #[test]
    fn test_planner_deduplicates_literals() {
        let mut planner = Planner::default();
        planner
            .call(
                addr(),
                CommandFlags::CALL,
                AddCall::selector(),
                vec![U256::from(1).into(), U256::from(1).into()],
                ParamType::Uint(256),
                Some(U256::zero()),
            )
            .expect("can add call");
        let (_, state) = planner.plan(vec![]).expect("plan");
        assert_eq!(state.len(), 1);
    }

    #[test]
    fn test_planner_return_values() {
        let mut planner = Planner::default();
        let ret = planner
            .call(
                addr(),
                CommandFlags::CALL,
                AddCall::selector(),
                vec![U256::from(1).into(), U256::from(2).into()],
                ParamType::Uint(256),
                Some(U256::zero()),
            )
            .expect("can add call");
        planner
            .call(
                addr(),
                CommandFlags::CALL,
                AddCall::selector(),
                vec![ret.into(), U256::from(3).into()],
                ParamType::Uint(256),
                Some(U256::zero()),
            )
            .expect("can add call with return val");
        let (commands, state) = planner.plan(vec![]).expect("plan");
        assert_eq!(commands.len(), 2);
        assert_eq!(
            commands[0],
            "0x771602f7010001ffffffff01eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
                .parse::<Bytes>()
                .unwrap()
        );
        assert_eq!(
            commands[1],
            "0x771602f7010102ffffffffffeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
                .parse::<Bytes>()
                .unwrap()
        );
        assert_eq!(state.len(), 3);
        assert_eq!(state[0], U256::from(1).encode());
        assert_eq!(state[1], U256::from(2).encode());
        assert_eq!(state[2], U256::from(3).encode());
    }

    #[test]
    fn test_planner_intermediate_state_slots() {
        // todo: how is this different from test_planner_return_values?
        let mut planner = Planner::default();
        let ret = planner
            .call(
                addr(),
                CommandFlags::CALL,
                AddCall::selector(),
                vec![U256::from(1).into(), U256::from(1).into()],
                ParamType::Uint(256),
                Some(U256::zero()),
            )
            .expect("can add call");
        planner
            .call(
                addr(),
                CommandFlags::CALL,
                AddCall::selector(),
                vec![U256::from(1).into(), ret.into()],
                ParamType::Uint(256),
                Some(U256::zero()),
            )
            .expect("can add call with return val");
        let (commands, state) = planner.plan(vec![]).expect("plan");
        assert_eq!(commands.len(), 2);
        assert_eq!(
            commands[0],
            "0x771602f7010000ffffffff01eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
                .parse::<Bytes>()
                .unwrap()
        );
        assert_eq!(
            commands[1],
            "0x771602f7010001ffffffffffeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
                .parse::<Bytes>()
                .unwrap()
        );
        assert_eq!(state.len(), 2);
        assert_eq!(state[0], U256::from(1).encode());
        assert_eq!(state[1], Bytes::default());
    }

    #[test]
    fn test_planner_dynamic_arguments() {
        let mut planner = Planner::default();
        planner
            .call(
                addr(),
                CommandFlags::CALL,
                StrlenCall::selector(),
                vec![String::from("Hello, world!").into()],
                ParamType::Uint(256),
                Some(U256::zero()),
            )
            .expect("can add call");
        let (commands, state) = planner.plan(vec![]).expect("plan");
        assert_eq!(commands.len(), 1);
        assert_eq!(
            commands[0],
            "0x367bbd780180ffffffffffffeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
                .parse::<Bytes>()
                .unwrap()
        );
        assert_eq!(state.len(), 1);
        assert_eq!(state[0], "Hello, world!".to_string().encode());
    }

    #[test]
    fn test_planner_dynamic_return_values() {
        let mut planner = Planner::default();
        let _ret = planner
            .call(
                addr(),
                CommandFlags::CALL,
                StrcatCall::selector(),
                vec![
                    String::from("Hello, ").into(),
                    String::from("world!").into(),
                ],
                ParamType::String,
                Some(U256::zero()),
            )
            .expect("can add call");
        let (commands, state) = planner.plan(vec![]).expect("plan");
        assert_eq!(commands.len(), 1);
        assert_eq!(
            commands[0],
            "0xd824ccf3018081ffffffffffeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
                .parse::<Bytes>()
                .unwrap()
        );
        assert_eq!(state.len(), 2);
        assert_eq!(state[0], "Hello, ".to_string().encode());
        assert_eq!(state[1], "world!".to_string().encode());
    }

    #[test]
    fn test_planner_dynamic_return_values_with_dynamic_arguments() {
        let mut planner = Planner::default();
        let ret = planner
            .call(
                addr(),
                CommandFlags::CALL,
                StrcatCall::selector(),
                vec![
                    String::from("Hello, ").into(),
                    String::from("world!").into(),
                ],
                ParamType::String,
                Some(U256::zero()),
            )
            .expect("can add call");
        planner
            .call(
                addr(),
                CommandFlags::CALL,
                StrlenCall::selector(),
                vec![ret.into()],
                ParamType::Uint(256),
                Some(U256::zero()),
            )
            .expect("can add call with return val");
        let (commands, state) = planner.plan(vec![]).expect("plan");
        assert_eq!(commands.len(), 2);
        assert_eq!(
            commands[0],
            "0xd824ccf3018081ffffffff81eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
                .parse::<Bytes>()
                .unwrap()
        );
        assert_eq!(
            commands[1],
            "0x367bbd780181ffffffffffffeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
                .parse::<Bytes>()
                .unwrap()
        );
        assert_eq!(state.len(), 2);
        assert_eq!(state[0], "Hello, ".to_string().encode());
        assert_eq!(state[1], "world!".to_string().encode());
    }

    #[test]
    fn test_planner_with_array() {
        let mut planner = Planner::default();
        let ret1 = planner
            .call(
                addr(),
                CommandFlags::CALL,
                AddCall::selector(),
                vec![U256::from(1).into(), U256::from(2).into()],
                ParamType::Uint(256),
                Some(U256::zero()),
            )
            .expect("can add call");

        let ret2 = planner
            .call(
                addr(),
                CommandFlags::CALL,
                AddCall::selector(),
                vec![U256::from(3).into(), U256::from(4).into()],
                ParamType::Uint(256),
                Some(U256::zero()),
            )
            .expect("can add call");

        planner
            .call(
                addr(),
                CommandFlags::CALL,
                SumCall::selector(),
                vec![Value::Array(vec![
                    ret1.into(),
                    ret2.into(),
                    U256::from(5).into(),
                ])],
                ParamType::Uint(256),
                Some(U256::zero()),
            )
            .expect("can add call");

        let (commands, state) = planner.plan(vec![]).expect("plan");

        println!("{:?}", commands);
        println!("{:?}", state);

        assert_eq!(commands.len(), 3);
        assert_eq!(state.len(), 5);

        assert_eq!(state[0], U256::from(1).encode());
        assert_eq!(state[1], U256::from(2).encode());
        assert_eq!(state[2], U256::from(4).encode());
        assert_eq!(state[3], U256::from(3).encode());
        assert_eq!(state[4], U256::from(5).encode());

        assert_eq!(
            commands[0],
            "0x771602f7010001ffffffff01eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
                .parse::<Bytes>()
                .unwrap()
        );

        assert_eq!(
            commands[1],
            "0x771602f7010302ffffffff02eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
                .parse::<Bytes>()
                .unwrap()
        );

        assert_eq!(
            commands[2],
            "0x0194db8e01fd03010204fbffeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
                .parse::<Bytes>()
                .unwrap()
        );
    }

    #[test]
    fn test_planner_flashloan_module() {
        let mut planner = Planner::default();

        planner
            .call(
                addr(),
                CommandFlags::CALL,
                [0x7b, 0xbe, 0xfc, 0x8d],
                vec![
                    Value::Tuple(vec![
                        U256::from(7).into(), // positionId
                        false.into(),         // isDebt
                        U256::from(3).into(), // instruction type
                        Value::Array(vec![]), // affected tokens
                        Value::Array(vec![]), // commands
                        Value::Array(vec![]), // state
                        U256::from(0).into(), // state bitmap
                        Value::Array(vec![    // merkle proof
                        H256::from_str(
                            "0xeec26e31960565573dd3a3c006488ebac583592f741b1d5149711f569c79a456",
                        )
                        .unwrap()
                        .into(),
                        H256::from_str(
                            "0xaf800c237b500dd633b370b7e38f5273c44e2b1903d6b27f462aabab36c2d3e2",
                        )
                        .unwrap()
                        .into(),
                        H256::from_str(
                            "0xddf902b24366aee097d551ff3ab0f7baf21988305fce1115f4ce00679a90a65d",
                        )
                        .unwrap()
                        .into(),
                        H256::from_str(
                            "0xb8456de2a9ef23360534d4dba17c574f93f6c3f1dc73368e7800811b49db736b",
                        )
                        .unwrap()
                        .into(),
                    ]),
                    ]),
                    "0xe54a55121A47451c5727ADBAF9b9FC1643477e25"
                        .parse::<Address>()
                        .unwrap()
                        .into(), // token
                    U256::exp10(18).into(), // amount
                ],
                ParamType::Uint(256),
                None,
            )
            .unwrap();

        let (commands, state) = planner.plan(vec![]).unwrap();

        println!("{:?}", commands);
        println!("{:?}", state);
    }
}
