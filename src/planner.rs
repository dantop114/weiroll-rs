use crate::calls::FunctionCall;
use crate::cmds::{
    Command, CommandFlags, CommandType, Literal, ReturnValue, Value, IDX_END_OF_ARGS,
    IDX_USE_STATE, IDX_VARIABLE_LENGTH,
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
        let dynamic = return_type.is_dynamic();
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
            let mut slot = match arg {
                Value::Return(val) => {
                    if let Some(slot) = return_slot_map.get(&val.command) {
                        *slot
                    } else {
                        return Err(WeirollError::MissingReturnSlot);
                    }
                }
                Value::Literal(val) => {
                    if let Some(slot) = literal_slot_map.get(val) {
                        *slot
                    } else {
                        return Err(WeirollError::MissingLiteralValue);
                    }
                }
                Value::State(_) => U256::from(IDX_USE_STATE),
            };
            // todo- correct??
            if arg.is_dynamic_type() {
                slot |= U256::from(IDX_VARIABLE_LENGTH);
            }

            args.push(slot);
        }

        Ok(args)
    }

    fn build_commands(&self, ps: &mut PlannerState) -> Result<Vec<Bytes>, WeirollError> {
        let mut encoded_commands = vec![];

        // Build commands, and add state entries as needed
        for (cmd_key, command) in &self.commands {
            let mut flags = command.call.flags;

            if flags == CommandFlags::CALL_WITH_VALUE_RETURN {
                flags = CommandFlags::CALL_WITH_VALUE;
            }

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

                let mut bytes = vec![
                    command.call.selector.into(),
                    flags.bits().to_le_bytes().to_vec().into(),
                ];

                bytes.extend(
                    pad_array(args.clone(), 6, U256::from(IDX_END_OF_ARGS))
                        .iter()
                        .map(|o| u256_bytes(*o)[0..1].to_vec().into()),
                );
                bytes.push(u256_bytes(ret)[0..1].to_vec().into());
                bytes.push(command.call.address.to_fixed_bytes().into());
                encoded_commands.push(concat_bytes(&bytes));
            }
        }

        Ok(encoded_commands)
    }

    fn preplan(
        &self,
        literal_visibility: &mut Vec<(Literal, CommandKey)>,
        command_visibility: &mut HashMap<CommandKey, CommandKey>,
        seen: &mut HashSet<CommandKey>,
        _planners: &mut HashSet<Planner>,
    ) -> Result<(), WeirollError> {
        for (cmd_key, command) in &self.commands {
            let in_args = &command.call.args;
            let mut extra_args = vec![];

            if command.call.flags & CommandFlags::CALLTYPE_MASK == CommandFlags::CALL_WITH_VALUE {
                if let Some(value) = command.call.value {
                    extra_args.push(value.into());
                } else {
                    return Err(WeirollError::MissingValue);
                }
            }

            if command.call.flags & CommandFlags::CALLTYPE_MASK
                == CommandFlags::CALL_WITH_VALUE_RETURN
                && command.call.value.is_none()
            {
                return Err(WeirollError::MissingValue);
            }

            for arg in extra_args.iter().chain(in_args.iter()) {
                match arg {
                    Value::Return(val) => {
                        if seen.contains(&val.command) {
                            command_visibility.insert(val.command, cmd_key);
                        }
                    }
                    Value::Literal(val) => {
                        // Remove old visibility (if exists)
                        literal_visibility.retain(|(l, _)| *l != *val);
                        literal_visibility.push((val.clone(), cmd_key));
                    }
                    Value::State(_) => {}
                }
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

    use crate::bindings::{
        math::AddCall,
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
                CommandFlags::CALL_WITH_VALUE_RETURN,
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
}
