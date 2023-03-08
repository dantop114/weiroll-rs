pub use math::*;
/// This module was auto-generated with ethers-rs Abigen.
/// More information at: <https://github.com/gakonst/ethers-rs>
#[allow(
    clippy::enum_variant_names,
    clippy::too_many_arguments,
    clippy::upper_case_acronyms,
    clippy::type_complexity,
    dead_code,
    non_camel_case_types,
)]
pub mod math {
    #[rustfmt::skip]
    const __ABI: &str = "[{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"a\",\"type\":\"uint256\",\"components\":[]},{\"internalType\":\"uint256\",\"name\":\"b\",\"type\":\"uint256\",\"components\":[]}],\"stateMutability\":\"pure\",\"type\":\"function\",\"name\":\"add\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\",\"components\":[]}]},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"a\",\"type\":\"uint256\",\"components\":[]},{\"internalType\":\"uint256\",\"name\":\"b\",\"type\":\"uint256\",\"components\":[]}],\"stateMutability\":\"pure\",\"type\":\"function\",\"name\":\"mul\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\",\"components\":[]}]},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"a\",\"type\":\"uint256\",\"components\":[]},{\"internalType\":\"uint256\",\"name\":\"b\",\"type\":\"uint256\",\"components\":[]}],\"stateMutability\":\"pure\",\"type\":\"function\",\"name\":\"sub\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\",\"components\":[]}]},{\"inputs\":[{\"internalType\":\"uint256[]\",\"name\":\"values\",\"type\":\"uint256[]\",\"components\":[]}],\"stateMutability\":\"pure\",\"type\":\"function\",\"name\":\"sum\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"ret\",\"type\":\"uint256\",\"components\":[]}]}]";
    ///The parsed JSON ABI of the contract.
    pub static MATH_ABI: ::ethers::contract::Lazy<::ethers::core::abi::Abi> = ::ethers::contract::Lazy::new(||
    ::ethers::core::utils::__serde_json::from_str(__ABI).expect("ABI is always valid"));
    #[rustfmt::skip]
    const __BYTECODE: &[u8] = &[
        96,
        128,
        96,
        64,
        82,
        52,
        128,
        21,
        97,
        0,
        16,
        87,
        96,
        0,
        128,
        253,
        91,
        80,
        97,
        2,
        118,
        128,
        97,
        0,
        32,
        96,
        0,
        57,
        96,
        0,
        243,
        254,
        96,
        128,
        96,
        64,
        82,
        52,
        128,
        21,
        97,
        0,
        16,
        87,
        96,
        0,
        128,
        253,
        91,
        80,
        96,
        4,
        54,
        16,
        97,
        0,
        76,
        87,
        96,
        0,
        53,
        96,
        224,
        28,
        128,
        99,
        1,
        148,
        219,
        142,
        20,
        97,
        0,
        81,
        87,
        128,
        99,
        119,
        22,
        2,
        247,
        20,
        97,
        0,
        118,
        87,
        128,
        99,
        182,
        125,
        119,
        197,
        20,
        97,
        0,
        137,
        87,
        128,
        99,
        200,
        164,
        172,
        156,
        20,
        97,
        0,
        156,
        87,
        91,
        96,
        0,
        128,
        253,
        91,
        97,
        0,
        100,
        97,
        0,
        95,
        54,
        96,
        4,
        97,
        1,
        39,
        86,
        91,
        97,
        0,
        175,
        86,
        91,
        96,
        64,
        81,
        144,
        129,
        82,
        96,
        32,
        1,
        96,
        64,
        81,
        128,
        145,
        3,
        144,
        243,
        91,
        97,
        0,
        100,
        97,
        0,
        132,
        54,
        96,
        4,
        97,
        1,
        156,
        86,
        91,
        97,
        0,
        250,
        86,
        91,
        97,
        0,
        100,
        97,
        0,
        151,
        54,
        96,
        4,
        97,
        1,
        156,
        86,
        91,
        97,
        1,
        15,
        86,
        91,
        97,
        0,
        100,
        97,
        0,
        170,
        54,
        96,
        4,
        97,
        1,
        156,
        86,
        91,
        97,
        1,
        27,
        86,
        91,
        96,
        0,
        129,
        129,
        91,
        129,
        129,
        16,
        21,
        97,
        0,
        242,
        87,
        132,
        132,
        130,
        129,
        129,
        16,
        97,
        0,
        206,
        87,
        97,
        0,
        206,
        97,
        1,
        190,
        86,
        91,
        144,
        80,
        96,
        32,
        2,
        1,
        53,
        131,
        97,
        0,
        224,
        145,
        144,
        97,
        1,
        234,
        86,
        91,
        146,
        80,
        97,
        0,
        235,
        129,
        97,
        1,
        253,
        86,
        91,
        144,
        80,
        97,
        0,
        180,
        86,
        91,
        80,
        80,
        146,
        145,
        80,
        80,
        86,
        91,
        96,
        0,
        97,
        1,
        6,
        130,
        132,
        97,
        1,
        234,
        86,
        91,
        144,
        80,
        91,
        146,
        145,
        80,
        80,
        86,
        91,
        96,
        0,
        97,
        1,
        6,
        130,
        132,
        97,
        2,
        22,
        86,
        91,
        96,
        0,
        97,
        1,
        6,
        130,
        132,
        97,
        2,
        41,
        86,
        91,
        96,
        0,
        128,
        96,
        32,
        131,
        133,
        3,
        18,
        21,
        97,
        1,
        58,
        87,
        96,
        0,
        128,
        253,
        91,
        130,
        53,
        103,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        128,
        130,
        17,
        21,
        97,
        1,
        82,
        87,
        96,
        0,
        128,
        253,
        91,
        129,
        133,
        1,
        145,
        80,
        133,
        96,
        31,
        131,
        1,
        18,
        97,
        1,
        102,
        87,
        96,
        0,
        128,
        253,
        91,
        129,
        53,
        129,
        129,
        17,
        21,
        97,
        1,
        117,
        87,
        96,
        0,
        128,
        253,
        91,
        134,
        96,
        32,
        130,
        96,
        5,
        27,
        133,
        1,
        1,
        17,
        21,
        97,
        1,
        138,
        87,
        96,
        0,
        128,
        253,
        91,
        96,
        32,
        146,
        144,
        146,
        1,
        150,
        145,
        149,
        80,
        144,
        147,
        80,
        80,
        80,
        80,
        86,
        91,
        96,
        0,
        128,
        96,
        64,
        131,
        133,
        3,
        18,
        21,
        97,
        1,
        175,
        87,
        96,
        0,
        128,
        253,
        91,
        80,
        80,
        128,
        53,
        146,
        96,
        32,
        144,
        145,
        1,
        53,
        145,
        80,
        86,
        91,
        99,
        78,
        72,
        123,
        113,
        96,
        224,
        27,
        96,
        0,
        82,
        96,
        50,
        96,
        4,
        82,
        96,
        36,
        96,
        0,
        253,
        91,
        99,
        78,
        72,
        123,
        113,
        96,
        224,
        27,
        96,
        0,
        82,
        96,
        17,
        96,
        4,
        82,
        96,
        36,
        96,
        0,
        253,
        91,
        128,
        130,
        1,
        128,
        130,
        17,
        21,
        97,
        1,
        9,
        87,
        97,
        1,
        9,
        97,
        1,
        212,
        86,
        91,
        96,
        0,
        96,
        1,
        130,
        1,
        97,
        2,
        15,
        87,
        97,
        2,
        15,
        97,
        1,
        212,
        86,
        91,
        80,
        96,
        1,
        1,
        144,
        86,
        91,
        129,
        129,
        3,
        129,
        129,
        17,
        21,
        97,
        1,
        9,
        87,
        97,
        1,
        9,
        97,
        1,
        212,
        86,
        91,
        128,
        130,
        2,
        129,
        21,
        130,
        130,
        4,
        132,
        20,
        23,
        97,
        1,
        9,
        87,
        97,
        1,
        9,
        97,
        1,
        212,
        86,
        254,
        162,
        100,
        105,
        112,
        102,
        115,
        88,
        34,
        18,
        32,
        105,
        84,
        130,
        160,
        109,
        46,
        225,
        151,
        20,
        111,
        253,
        44,
        11,
        131,
        10,
        202,
        2,
        165,
        165,
        32,
        187,
        29,
        62,
        5,
        123,
        102,
        78,
        96,
        108,
        164,
        130,
        184,
        100,
        115,
        111,
        108,
        99,
        67,
        0,
        8,
        17,
        0,
        51,
    ];
    ///The bytecode of the contract.
    pub static MATH_BYTECODE: ::ethers::core::types::Bytes = ::ethers::core::types::Bytes::from_static(
        __BYTECODE,
    );
    #[rustfmt::skip]
    const __DEPLOYED_BYTECODE: &[u8] = &[
        96,
        128,
        96,
        64,
        82,
        52,
        128,
        21,
        97,
        0,
        16,
        87,
        96,
        0,
        128,
        253,
        91,
        80,
        96,
        4,
        54,
        16,
        97,
        0,
        76,
        87,
        96,
        0,
        53,
        96,
        224,
        28,
        128,
        99,
        1,
        148,
        219,
        142,
        20,
        97,
        0,
        81,
        87,
        128,
        99,
        119,
        22,
        2,
        247,
        20,
        97,
        0,
        118,
        87,
        128,
        99,
        182,
        125,
        119,
        197,
        20,
        97,
        0,
        137,
        87,
        128,
        99,
        200,
        164,
        172,
        156,
        20,
        97,
        0,
        156,
        87,
        91,
        96,
        0,
        128,
        253,
        91,
        97,
        0,
        100,
        97,
        0,
        95,
        54,
        96,
        4,
        97,
        1,
        39,
        86,
        91,
        97,
        0,
        175,
        86,
        91,
        96,
        64,
        81,
        144,
        129,
        82,
        96,
        32,
        1,
        96,
        64,
        81,
        128,
        145,
        3,
        144,
        243,
        91,
        97,
        0,
        100,
        97,
        0,
        132,
        54,
        96,
        4,
        97,
        1,
        156,
        86,
        91,
        97,
        0,
        250,
        86,
        91,
        97,
        0,
        100,
        97,
        0,
        151,
        54,
        96,
        4,
        97,
        1,
        156,
        86,
        91,
        97,
        1,
        15,
        86,
        91,
        97,
        0,
        100,
        97,
        0,
        170,
        54,
        96,
        4,
        97,
        1,
        156,
        86,
        91,
        97,
        1,
        27,
        86,
        91,
        96,
        0,
        129,
        129,
        91,
        129,
        129,
        16,
        21,
        97,
        0,
        242,
        87,
        132,
        132,
        130,
        129,
        129,
        16,
        97,
        0,
        206,
        87,
        97,
        0,
        206,
        97,
        1,
        190,
        86,
        91,
        144,
        80,
        96,
        32,
        2,
        1,
        53,
        131,
        97,
        0,
        224,
        145,
        144,
        97,
        1,
        234,
        86,
        91,
        146,
        80,
        97,
        0,
        235,
        129,
        97,
        1,
        253,
        86,
        91,
        144,
        80,
        97,
        0,
        180,
        86,
        91,
        80,
        80,
        146,
        145,
        80,
        80,
        86,
        91,
        96,
        0,
        97,
        1,
        6,
        130,
        132,
        97,
        1,
        234,
        86,
        91,
        144,
        80,
        91,
        146,
        145,
        80,
        80,
        86,
        91,
        96,
        0,
        97,
        1,
        6,
        130,
        132,
        97,
        2,
        22,
        86,
        91,
        96,
        0,
        97,
        1,
        6,
        130,
        132,
        97,
        2,
        41,
        86,
        91,
        96,
        0,
        128,
        96,
        32,
        131,
        133,
        3,
        18,
        21,
        97,
        1,
        58,
        87,
        96,
        0,
        128,
        253,
        91,
        130,
        53,
        103,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        128,
        130,
        17,
        21,
        97,
        1,
        82,
        87,
        96,
        0,
        128,
        253,
        91,
        129,
        133,
        1,
        145,
        80,
        133,
        96,
        31,
        131,
        1,
        18,
        97,
        1,
        102,
        87,
        96,
        0,
        128,
        253,
        91,
        129,
        53,
        129,
        129,
        17,
        21,
        97,
        1,
        117,
        87,
        96,
        0,
        128,
        253,
        91,
        134,
        96,
        32,
        130,
        96,
        5,
        27,
        133,
        1,
        1,
        17,
        21,
        97,
        1,
        138,
        87,
        96,
        0,
        128,
        253,
        91,
        96,
        32,
        146,
        144,
        146,
        1,
        150,
        145,
        149,
        80,
        144,
        147,
        80,
        80,
        80,
        80,
        86,
        91,
        96,
        0,
        128,
        96,
        64,
        131,
        133,
        3,
        18,
        21,
        97,
        1,
        175,
        87,
        96,
        0,
        128,
        253,
        91,
        80,
        80,
        128,
        53,
        146,
        96,
        32,
        144,
        145,
        1,
        53,
        145,
        80,
        86,
        91,
        99,
        78,
        72,
        123,
        113,
        96,
        224,
        27,
        96,
        0,
        82,
        96,
        50,
        96,
        4,
        82,
        96,
        36,
        96,
        0,
        253,
        91,
        99,
        78,
        72,
        123,
        113,
        96,
        224,
        27,
        96,
        0,
        82,
        96,
        17,
        96,
        4,
        82,
        96,
        36,
        96,
        0,
        253,
        91,
        128,
        130,
        1,
        128,
        130,
        17,
        21,
        97,
        1,
        9,
        87,
        97,
        1,
        9,
        97,
        1,
        212,
        86,
        91,
        96,
        0,
        96,
        1,
        130,
        1,
        97,
        2,
        15,
        87,
        97,
        2,
        15,
        97,
        1,
        212,
        86,
        91,
        80,
        96,
        1,
        1,
        144,
        86,
        91,
        129,
        129,
        3,
        129,
        129,
        17,
        21,
        97,
        1,
        9,
        87,
        97,
        1,
        9,
        97,
        1,
        212,
        86,
        91,
        128,
        130,
        2,
        129,
        21,
        130,
        130,
        4,
        132,
        20,
        23,
        97,
        1,
        9,
        87,
        97,
        1,
        9,
        97,
        1,
        212,
        86,
        254,
        162,
        100,
        105,
        112,
        102,
        115,
        88,
        34,
        18,
        32,
        105,
        84,
        130,
        160,
        109,
        46,
        225,
        151,
        20,
        111,
        253,
        44,
        11,
        131,
        10,
        202,
        2,
        165,
        165,
        32,
        187,
        29,
        62,
        5,
        123,
        102,
        78,
        96,
        108,
        164,
        130,
        184,
        100,
        115,
        111,
        108,
        99,
        67,
        0,
        8,
        17,
        0,
        51,
    ];
    ///The deployed bytecode of the contract.
    pub static MATH_DEPLOYED_BYTECODE: ::ethers::core::types::Bytes = ::ethers::core::types::Bytes::from_static(
        __DEPLOYED_BYTECODE,
    );
    pub struct Math<M>(::ethers::contract::Contract<M>);
    impl<M> ::core::clone::Clone for Math<M> {
        fn clone(&self) -> Self {
            Self(::core::clone::Clone::clone(&self.0))
        }
    }
    impl<M> ::core::ops::Deref for Math<M> {
        type Target = ::ethers::contract::Contract<M>;
        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }
    impl<M> ::core::ops::DerefMut for Math<M> {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.0
        }
    }
    impl<M> ::core::fmt::Debug for Math<M> {
        fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
            f.debug_tuple(stringify!(Math)).field(&self.address()).finish()
        }
    }
    impl<M: ::ethers::providers::Middleware> Math<M> {
        /// Creates a new contract instance with the specified `ethers` client at
        /// `address`. The contract derefs to a `ethers::Contract` object.
        pub fn new<T: Into<::ethers::core::types::Address>>(
            address: T,
            client: ::std::sync::Arc<M>,
        ) -> Self {
            Self(
                ::ethers::contract::Contract::new(
                    address.into(),
                    MATH_ABI.clone(),
                    client,
                ),
            )
        }
        /// Constructs the general purpose `Deployer` instance based on the provided constructor arguments and sends it.
        /// Returns a new instance of a deployer that returns an instance of this contract after sending the transaction
        ///
        /// Notes:
        /// - If there are no constructor arguments, you should pass `()` as the argument.
        /// - The default poll duration is 7 seconds.
        /// - The default number of confirmations is 1 block.
        ///
        ///
        /// # Example
        ///
        /// Generate contract bindings with `abigen!` and deploy a new contract instance.
        ///
        /// *Note*: this requires a `bytecode` and `abi` object in the `greeter.json` artifact.
        ///
        /// ```ignore
        /// # async fn deploy<M: ethers::providers::Middleware>(client: ::std::sync::Arc<M>) {
        ///     abigen!(Greeter, "../greeter.json");
        ///
        ///    let greeter_contract = Greeter::deploy(client, "Hello world!".to_string()).unwrap().send().await.unwrap();
        ///    let msg = greeter_contract.greet().call().await.unwrap();
        /// # }
        /// ```
        pub fn deploy<T: ::ethers::core::abi::Tokenize>(
            client: ::std::sync::Arc<M>,
            constructor_args: T,
        ) -> ::core::result::Result<
            ::ethers::contract::builders::ContractDeployer<M, Self>,
            ::ethers::contract::ContractError<M>,
        > {
            let factory = ::ethers::contract::ContractFactory::new(
                MATH_ABI.clone(),
                MATH_BYTECODE.clone().into(),
                client,
            );
            let deployer = factory.deploy(constructor_args)?;
            let deployer = ::ethers::contract::ContractDeployer::new(deployer);
            Ok(deployer)
        }
        ///Calls the contract's `add` (0x771602f7) function
        pub fn add(
            &self,
            a: ::ethers::core::types::U256,
            b: ::ethers::core::types::U256,
        ) -> ::ethers::contract::builders::ContractCall<M, ::ethers::core::types::U256> {
            self.0
                .method_hash([119, 22, 2, 247], (a, b))
                .expect("method not found (this should never happen)")
        }
        ///Calls the contract's `mul` (0xc8a4ac9c) function
        pub fn mul(
            &self,
            a: ::ethers::core::types::U256,
            b: ::ethers::core::types::U256,
        ) -> ::ethers::contract::builders::ContractCall<M, ::ethers::core::types::U256> {
            self.0
                .method_hash([200, 164, 172, 156], (a, b))
                .expect("method not found (this should never happen)")
        }
        ///Calls the contract's `sub` (0xb67d77c5) function
        pub fn sub(
            &self,
            a: ::ethers::core::types::U256,
            b: ::ethers::core::types::U256,
        ) -> ::ethers::contract::builders::ContractCall<M, ::ethers::core::types::U256> {
            self.0
                .method_hash([182, 125, 119, 197], (a, b))
                .expect("method not found (this should never happen)")
        }
        ///Calls the contract's `sum` (0x0194db8e) function
        pub fn sum(
            &self,
            values: ::std::vec::Vec<::ethers::core::types::U256>,
        ) -> ::ethers::contract::builders::ContractCall<M, ::ethers::core::types::U256> {
            self.0
                .method_hash([1, 148, 219, 142], values)
                .expect("method not found (this should never happen)")
        }
    }
    impl<M: ::ethers::providers::Middleware> From<::ethers::contract::Contract<M>>
    for Math<M> {
        fn from(contract: ::ethers::contract::Contract<M>) -> Self {
            Self::new(contract.address(), contract.client())
        }
    }
    ///Container type for all input parameters for the `add` function with signature `add(uint256,uint256)` and selector `0x771602f7`
    #[derive(
        Clone,
        ::ethers::contract::EthCall,
        ::ethers::contract::EthDisplay,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    #[ethcall(name = "add", abi = "add(uint256,uint256)")]
    pub struct AddCall {
        pub a: ::ethers::core::types::U256,
        pub b: ::ethers::core::types::U256,
    }
    ///Container type for all input parameters for the `mul` function with signature `mul(uint256,uint256)` and selector `0xc8a4ac9c`
    #[derive(
        Clone,
        ::ethers::contract::EthCall,
        ::ethers::contract::EthDisplay,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    #[ethcall(name = "mul", abi = "mul(uint256,uint256)")]
    pub struct MulCall {
        pub a: ::ethers::core::types::U256,
        pub b: ::ethers::core::types::U256,
    }
    ///Container type for all input parameters for the `sub` function with signature `sub(uint256,uint256)` and selector `0xb67d77c5`
    #[derive(
        Clone,
        ::ethers::contract::EthCall,
        ::ethers::contract::EthDisplay,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    #[ethcall(name = "sub", abi = "sub(uint256,uint256)")]
    pub struct SubCall {
        pub a: ::ethers::core::types::U256,
        pub b: ::ethers::core::types::U256,
    }
    ///Container type for all input parameters for the `sum` function with signature `sum(uint256[])` and selector `0x0194db8e`
    #[derive(
        Clone,
        ::ethers::contract::EthCall,
        ::ethers::contract::EthDisplay,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    #[ethcall(name = "sum", abi = "sum(uint256[])")]
    pub struct SumCall {
        pub values: ::std::vec::Vec<::ethers::core::types::U256>,
    }
    ///Container type for all of the contract's call
    #[derive(Clone, ::ethers::contract::EthAbiType, Debug, PartialEq, Eq, Hash)]
    pub enum MathCalls {
        Add(AddCall),
        Mul(MulCall),
        Sub(SubCall),
        Sum(SumCall),
    }
    impl ::ethers::core::abi::AbiDecode for MathCalls {
        fn decode(
            data: impl AsRef<[u8]>,
        ) -> ::core::result::Result<Self, ::ethers::core::abi::AbiError> {
            let data = data.as_ref();
            if let Ok(decoded)
                = <AddCall as ::ethers::core::abi::AbiDecode>::decode(data) {
                return Ok(Self::Add(decoded));
            }
            if let Ok(decoded)
                = <MulCall as ::ethers::core::abi::AbiDecode>::decode(data) {
                return Ok(Self::Mul(decoded));
            }
            if let Ok(decoded)
                = <SubCall as ::ethers::core::abi::AbiDecode>::decode(data) {
                return Ok(Self::Sub(decoded));
            }
            if let Ok(decoded)
                = <SumCall as ::ethers::core::abi::AbiDecode>::decode(data) {
                return Ok(Self::Sum(decoded));
            }
            Err(::ethers::core::abi::Error::InvalidData.into())
        }
    }
    impl ::ethers::core::abi::AbiEncode for MathCalls {
        fn encode(self) -> Vec<u8> {
            match self {
                Self::Add(element) => ::ethers::core::abi::AbiEncode::encode(element),
                Self::Mul(element) => ::ethers::core::abi::AbiEncode::encode(element),
                Self::Sub(element) => ::ethers::core::abi::AbiEncode::encode(element),
                Self::Sum(element) => ::ethers::core::abi::AbiEncode::encode(element),
            }
        }
    }
    impl ::core::fmt::Display for MathCalls {
        fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
            match self {
                Self::Add(element) => ::core::fmt::Display::fmt(element, f),
                Self::Mul(element) => ::core::fmt::Display::fmt(element, f),
                Self::Sub(element) => ::core::fmt::Display::fmt(element, f),
                Self::Sum(element) => ::core::fmt::Display::fmt(element, f),
            }
        }
    }
    impl ::core::convert::From<AddCall> for MathCalls {
        fn from(value: AddCall) -> Self {
            Self::Add(value)
        }
    }
    impl ::core::convert::From<MulCall> for MathCalls {
        fn from(value: MulCall) -> Self {
            Self::Mul(value)
        }
    }
    impl ::core::convert::From<SubCall> for MathCalls {
        fn from(value: SubCall) -> Self {
            Self::Sub(value)
        }
    }
    impl ::core::convert::From<SumCall> for MathCalls {
        fn from(value: SumCall) -> Self {
            Self::Sum(value)
        }
    }
    ///Container type for all return fields from the `add` function with signature `add(uint256,uint256)` and selector `0x771602f7`
    #[derive(
        Clone,
        ::ethers::contract::EthAbiType,
        ::ethers::contract::EthAbiCodec,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    pub struct AddReturn(pub ::ethers::core::types::U256);
    ///Container type for all return fields from the `mul` function with signature `mul(uint256,uint256)` and selector `0xc8a4ac9c`
    #[derive(
        Clone,
        ::ethers::contract::EthAbiType,
        ::ethers::contract::EthAbiCodec,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    pub struct MulReturn(pub ::ethers::core::types::U256);
    ///Container type for all return fields from the `sub` function with signature `sub(uint256,uint256)` and selector `0xb67d77c5`
    #[derive(
        Clone,
        ::ethers::contract::EthAbiType,
        ::ethers::contract::EthAbiCodec,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    pub struct SubReturn(pub ::ethers::core::types::U256);
    ///Container type for all return fields from the `sum` function with signature `sum(uint256[])` and selector `0x0194db8e`
    #[derive(
        Clone,
        ::ethers::contract::EthAbiType,
        ::ethers::contract::EthAbiCodec,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    pub struct SumReturn {
        pub ret: ::ethers::core::types::U256,
    }
}
