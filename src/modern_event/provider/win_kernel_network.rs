use super::*;

#[derive(Debug)]
pub struct MicrosoftWindowsKernelNetwork {
    modern_event: crate::modern_event::ModernEvent,
    payload: ::core::option::Option<
        ::std::collections::HashMap<&'static str, crate::modern_event::types::WinInTypeItem>,
    >,
}
impl MicrosoftWindowsKernelNetwork {
    pub const MICROSOFT_WINDOWS_KERNEL_NETWORK: Uuid =
        uuid!("{7dd42a49-5329-4832-8dfd-43d979153a88}");
}
impl ::core::ops::Deref for MicrosoftWindowsKernelNetwork {
    type Target = crate::modern_event::ModernEvent;
    fn deref(&self) -> &Self::Target {
        &self.modern_event
    }
}
impl ::core::ops::DerefMut for MicrosoftWindowsKernelNetwork {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.modern_event
    }
}
impl ::core::convert::TryFrom<crate::modern_event::ModernEvent> for MicrosoftWindowsKernelNetwork {
    type Error = &'static str;
    fn try_from(
        value: crate::modern_event::ModernEvent,
    ) -> ::core::result::Result<Self, Self::Error> {
        if matches!(
            value.header.provider_id,
            Self::MICROSOFT_WINDOWS_KERNEL_NETWORK
        ) {
            Ok(Self {
                modern_event: value,
                payload: None,
            })
        } else {
            Err("GUID of event doesn't match")
        }
    }
}
impl Event for MicrosoftWindowsKernelNetwork {
    fn get_provider_name(&self) -> &str {
        "Microsoft-Windows-Kernel-Network"
    }
    fn get_event_task_name(&self) -> Option<&str> {
        match self.header.event_descriptor.id {
            10 => Some("KERNEL_NETWORK_TASK_TCPIP"),
            11 => Some("KERNEL_NETWORK_TASK_UDPIP"),
            _ => None,
        }
    }
    fn get_event_symbol(&self) -> Option<&str> {
        let ed = &self.header.event_descriptor;
        match (ed.id, ed.version) {
            (10, 0) => Some("KERNEL_NETWORK_TASK_TCPIPDatasent."),
            (11, 0) => Some("KERNEL_NETWORK_TASK_TCPIPDatareceived."),
            (12, 0) => Some("KERNEL_NETWORK_TASK_TCPIPConnectionattempted."),
            (13, 0) => Some("KERNEL_NETWORK_TASK_TCPIPDisconnectissued."),
            (14, 0) => Some("KERNEL_NETWORK_TASK_TCPIPDataretransmitted."),
            (15, 0) => Some("KERNEL_NETWORK_TASK_TCPIPConnectionaccepted."),
            (16, 0) => Some("KERNEL_NETWORK_TASK_TCPIPReconnectattempted."),
            (17, 0) => Some("KERNEL_NETWORK_TASK_TCPIPTCPconnectionattemptfailed."),
            (18, 0) => Some("KERNEL_NETWORK_TASK_TCPIPProtocolcopieddataonbehalfofuser."),
            (19, 0) => Some("KERNEL_NETWORK_TASK_TCPIPDatasent.26"),
            (26, 0) => Some("KERNEL_NETWORK_TASK_TCPIPDatareceived.27"),
            (27, 0) => Some("KERNEL_NETWORK_TASK_TCPIPConnectionattempted.28"),
            (28, 0) => Some("KERNEL_NETWORK_TASK_TCPIPDisconnectissued.29"),
            (29, 0) => Some("KERNEL_NETWORK_TASK_TCPIPDataretransmitted.30"),
            (30, 0) => Some("KERNEL_NETWORK_TASK_TCPIPConnectionaccepted.31"),
            (31, 0) => Some("KERNEL_NETWORK_TASK_TCPIPReconnectattempted.32"),
            (32, 0) => Some("KERNEL_NETWORK_TASK_TCPIPProtocolcopieddataonbehalfofuser.34"),
            (34, 0) => Some("KERNEL_NETWORK_TASK_UDPIPDatasentoverUDPprotocol."),
            (42, 0) => Some("KERNEL_NETWORK_TASK_UDPIPDatareceivedoverUDPprotocol."),
            (43, 0) => Some("KERNEL_NETWORK_TASK_UDPIPUDPconnectionattemptfailed."),
            (49, 0) => Some("KERNEL_NETWORK_TASK_UDPIPDatasentoverUDPprotocol.58"),
            (58, 0) => Some("KERNEL_NETWORK_TASK_UDPIPDatareceivedoverUDPprotocol.59"),
            (59, 0) => Some("KERNEL_NETWORK_TASK_UDPIPDatareceivedoverUDPprotocol.59"),
            _ => None,
        }
    }
    fn get_keywords(&self) -> Vec<&'static str> {
        let ed = &self.header.event_descriptor;
        let mut keywords = ::std::vec::Vec::new();
        if ed.keywords & 10 != 0x0 {
            keywords.push("KERNEL_NETWORK_KEYWORD_IPV4")
        }
        if ed.keywords & 20 != 0x0 {
            keywords.push("KERNEL_NETWORK_KEYWORD_IPV6")
        }

        keywords
    }
    fn get_payload_items(
        &mut self,
    ) -> Option<&HashMap<&'static str, crate::modern_event::types::WinInTypeItem>> {
        if self.payload.is_some() {
            return self.payload.as_ref();
        }

        let ed = &self.header.event_descriptor;
        match (ed.id, ed.version) {
            // #(#event_to_template => {
            //     let res = self.#template_fn();
            //     if let Err(e) = res {
            //         ::log::warn!("Parsing of payload items failed: {e}");
            //     }
            // })*
            (10, 0) => {
                let res = self.datasent_args();
                if let Err(e) = res {
                    ::log::warn!("Parsing of payload items failed: {e}");
                }
            }
            (11, 0) => {
                let res = self.datareceived_args();
                if let Err(e) = res {
                    ::log::warn!("Parsing of payload items failed: {e}");
                }
            }
            (12, 0) => {
                let res = self.connectionattempted_args();
                if let Err(e) = res {
                    ::log::warn!("Parsing of payload items failed: {e}");
                }
            }
            (13, 0) => {
                let res = self.datareceived_args();
                if let Err(e) = res {
                    ::log::warn!("Parsing of payload items failed: {e}");
                }
            }
            (14, 0) => {
                let res = self.datareceived_args();
                if let Err(e) = res {
                    ::log::warn!("Parsing of payload items failed: {e}");
                }
            }
            (15, 0) => {
                let res = self.connectionattempted_args();
                if let Err(e) = res {
                    ::log::warn!("Parsing of payload items failed: {e}");
                }
            }
            (16, 0) => {
                let res = self.datareceived_args();
                if let Err(e) = res {
                    ::log::warn!("Parsing of payload items failed: {e}");
                }
            }
            (17, 0) => {
                let res = self.tcp_connectionattemptfailed_args();
                if let Err(e) = res {
                    ::log::warn!("Parsing of payload items failed: {e}");
                }
            }
            (18, 0) => {
                let res = self.datareceived_args();
                if let Err(e) = res {
                    ::log::warn!("Parsing of payload items failed: {e}");
                }
            }
            (26, 0) => {
                let res = self.datasent_26_args();
                if let Err(e) = res {
                    ::log::warn!("Parsing of payload items failed: {e}");
                }
            }
            (27, 0) => {
                let res = self.datareceived_27_args();
                if let Err(e) = res {
                    ::log::warn!("Parsing of payload items failed: {e}");
                }
            }
            (28, 0) => {
                let res = self.connectionattempted_28_args();
                if let Err(e) = res {
                    ::log::warn!("Parsing of payload items failed: {e}");
                }
            }
            (29, 0) => {
                let res = self.datareceived_27_args();
                if let Err(e) = res {
                    ::log::warn!("Parsing of payload items failed: {e}");
                }
            }
            (30, 0) => {
                let res = self.datareceived_27_args();
                if let Err(e) = res {
                    ::log::warn!("Parsing of payload items failed: {e}");
                }
            }
            (31, 0) => {
                let res = self.connectionattempted_28_args();
                if let Err(e) = res {
                    ::log::warn!("Parsing of payload items failed: {e}");
                }
            }
            (32, 0) => {
                let res = self.datareceived_27_args();
                if let Err(e) = res {
                    ::log::warn!("Parsing of payload items failed: {e}");
                }
            }
            (34, 0) => {
                let res = self.datareceived_27_args();
                if let Err(e) = res {
                    ::log::warn!("Parsing of payload items failed: {e}");
                }
            }
            (42, 0) => {
                let res = self.datareceived_args();
                if let Err(e) = res {
                    ::log::warn!("Parsing of payload items failed: {e}");
                }
            }
            (43, 0) => {
                let res = self.datareceived_args();
                if let Err(e) = res {
                    ::log::warn!("Parsing of payload items failed: {e}");
                }
            }
            (49, 0) => {
                let res = self.tcp_connectionattemptfailed_args();
                if let Err(e) = res {
                    ::log::warn!("Parsing of payload items failed: {e}");
                }
            }
            (58, 0) => {
                let res = self.datareceived_27_args();
                if let Err(e) = res {
                    ::log::warn!("Parsing of payload items failed: {e}");
                }
            }
            (59, 0) => {
                let res = self.datareceived_27_args();
                if let Err(e) = res {
                    ::log::warn!("Parsing of payload items failed: {e}");
                }
            }
            _ => {}
        }
        self.payload.as_ref()
    }
}

impl MicrosoftWindowsKernelNetwork {
    fn datasent_args(&mut self) -> Result<(), ModernEventError> {
        // <data name="PID" inType="win:UInt32"/>
        // <data name="size" inType="win:UInt32"/>
        // <data name="daddr" inType="win:UInt32"/>
        // <data name="saddr" inType="win:UInt32"/>
        // <data name="dport" inType="win:UInt16"/>
        // <data name="sport" inType="win:UInt16"/>
        // <data name="startime" inType="win:UInt32"/>
        // <data name="endtime" inType="win:UInt32"/>
        // <data name="seqnum" inType="win:UInt32"/>
        // <data name="connid" inType="win:UInt32"/>

        let mut map: ::std::collections::HashMap<&str, crate::modern_event::types::WinInTypeItem> =
            ::std::collections::HashMap::new();

        map.insert(
            "PID",
            self.modern_event
                .read_payload_item(crate::modern_event::WinInType::UInt32, None)?,
        );
        map.insert(
            "size",
            self.modern_event
                .read_payload_item(crate::modern_event::WinInType::UInt32, None)?,
        );
        map.insert(
            "daddr",
            self.modern_event
                .read_payload_item(crate::modern_event::WinInType::UInt32, None)?,
        );
        map.insert(
            "saddr",
            self.modern_event
                .read_payload_item(crate::modern_event::WinInType::UInt32, None)?,
        );
        map.insert(
            "dport",
            self.modern_event
                .read_payload_item(crate::modern_event::WinInType::UInt16, None)?,
        );
        map.insert(
            "sport",
            self.modern_event
                .read_payload_item(crate::modern_event::WinInType::UInt16, None)?,
        );
        map.insert(
            "startime",
            self.modern_event
                .read_payload_item(crate::modern_event::WinInType::UInt32, None)?,
        );
        map.insert(
            "endtime",
            self.modern_event
                .read_payload_item(crate::modern_event::WinInType::UInt32, None)?,
        );
        map.insert(
            "seqnum",
            self.modern_event
                .read_payload_item(crate::modern_event::WinInType::UInt32, None)?,
        );
        map.insert(
            "connid",
            self.modern_event
                .read_payload_item(crate::modern_event::WinInType::UInt32, None)?,
        );

        self.payload = Some(map);
        Ok(())
    }
    fn datareceived_args(&mut self) -> Result<(), ModernEventError> {
        // <data name="PID" inType="win:UInt32"/>
        // <data name="size" inType="win:UInt32"/>
        // <data name="daddr" inType="win:UInt32"/>
        // <data name="saddr" inType="win:UInt32"/>
        // <data name="dport" inType="win:UInt16"/>
        // <data name="sport" inType="win:UInt16"/>
        // <data name="seqnum" inType="win:UInt32"/>
        // <data name="connid" inType="win:UInt32"/>

        let mut map: ::std::collections::HashMap<&str, crate::modern_event::types::WinInTypeItem> =
            ::std::collections::HashMap::new();

        map.insert(
            "PID",
            self.modern_event
                .read_payload_item(crate::modern_event::WinInType::UInt32, None)?,
        );
        map.insert(
            "size",
            self.modern_event
                .read_payload_item(crate::modern_event::WinInType::UInt32, None)?,
        );
        map.insert(
            "daddr",
            self.modern_event
                .read_payload_item(crate::modern_event::WinInType::UInt32, None)?,
        );
        map.insert(
            "saddr",
            self.modern_event
                .read_payload_item(crate::modern_event::WinInType::UInt32, None)?,
        );
        map.insert(
            "dport",
            self.modern_event
                .read_payload_item(crate::modern_event::WinInType::UInt16, None)?,
        );
        map.insert(
            "sport",
            self.modern_event
                .read_payload_item(crate::modern_event::WinInType::UInt16, None)?,
        );
        map.insert(
            "seqnum",
            self.modern_event
                .read_payload_item(crate::modern_event::WinInType::UInt32, None)?,
        );
        map.insert(
            "connid",
            self.modern_event
                .read_payload_item(crate::modern_event::WinInType::UInt32, None)?,
        );

        self.payload = Some(map);
        Ok(())
    }
    fn connectionattempted_args(&mut self) -> Result<(), ModernEventError> {
        // <data name="PID" inType="win:UInt32"/>
        // <data name="size" inType="win:UInt32"/>
        // <data name="daddr" inType="win:UInt32"/>
        // <data name="saddr" inType="win:UInt32"/>
        // <data name="dport" inType="win:UInt16"/>
        // <data name="sport" inType="win:UInt16"/>
        // <data name="mss" inType="win:UInt16"/>
        // <data name="sackopt" inType="win:UInt16"/>
        // <data name="tsopt" inType="win:UInt16"/>
        // <data name="wsopt" inType="win:UInt16"/>
        // <data name="rcvwin" inType="win:UInt32"/>
        // <data name="rcvwinscale" inType="win:UInt16"/>
        // <data name="sndwinscale" inType="win:UInt16"/>
        // <data name="seqnum" inType="win:UInt32"/>
        // <data name="connid" inType="win:UInt32"/>

        let mut map: ::std::collections::HashMap<&str, crate::modern_event::types::WinInTypeItem> =
            ::std::collections::HashMap::new();

        map.insert(
            "PID",
            self.modern_event
                .read_payload_item(crate::modern_event::WinInType::UInt32, None)?,
        );
        map.insert(
            "size",
            self.modern_event
                .read_payload_item(crate::modern_event::WinInType::UInt32, None)?,
        );
        map.insert(
            "daddr",
            self.modern_event
                .read_payload_item(crate::modern_event::WinInType::UInt32, None)?,
        );
        map.insert(
            "saddr",
            self.modern_event
                .read_payload_item(crate::modern_event::WinInType::UInt32, None)?,
        );
        map.insert(
            "dport",
            self.modern_event
                .read_payload_item(crate::modern_event::WinInType::UInt16, None)?,
        );
        map.insert(
            "sport",
            self.modern_event
                .read_payload_item(crate::modern_event::WinInType::UInt16, None)?,
        );
        map.insert(
            "mss",
            self.modern_event
                .read_payload_item(crate::modern_event::WinInType::UInt16, None)?,
        );
        map.insert(
            "sackopt",
            self.modern_event
                .read_payload_item(crate::modern_event::WinInType::UInt16, None)?,
        );
        map.insert(
            "tsopt",
            self.modern_event
                .read_payload_item(crate::modern_event::WinInType::UInt16, None)?,
        );
        map.insert(
            "wsopt",
            self.modern_event
                .read_payload_item(crate::modern_event::WinInType::UInt16, None)?,
        );
        map.insert(
            "rcvwin",
            self.modern_event
                .read_payload_item(crate::modern_event::WinInType::UInt32, None)?,
        );
        map.insert(
            "rcvwinscale",
            self.modern_event
                .read_payload_item(crate::modern_event::WinInType::UInt16, None)?,
        );
        map.insert(
            "sndwinscale",
            self.modern_event
                .read_payload_item(crate::modern_event::WinInType::UInt16, None)?,
        );
        map.insert(
            "seqnum",
            self.modern_event
                .read_payload_item(crate::modern_event::WinInType::UInt32, None)?,
        );
        map.insert(
            "connid",
            self.modern_event
                .read_payload_item(crate::modern_event::WinInType::UInt32, None)?,
        );

        self.payload = Some(map);
        Ok(())
    }
    fn tcp_connectionattemptfailed_args(&mut self) -> Result<(), ModernEventError> {
        // <data name="Proto" inType="win:UInt16"/>
        // <data name="FailureCode" inType="win:UInt16"/>

        let mut map: ::std::collections::HashMap<&str, crate::modern_event::types::WinInTypeItem> =
            ::std::collections::HashMap::new();

        map.insert(
            "Proto",
            self.modern_event
                .read_payload_item(crate::modern_event::WinInType::UInt16, None)?,
        );
        map.insert(
            "FailureCode",
            self.modern_event
                .read_payload_item(crate::modern_event::WinInType::UInt16, None)?,
        );

        self.payload = Some(map);
        Ok(())
    }
    fn datasent_26_args(&mut self) -> Result<(), ModernEventError> {
        // <data name="PID" inType="win:UInt32"/>
        // <data name="size" inType="win:UInt32"/>
        // <data name="daddr" inType="win:Binary"/>
        // <data name="saddr" inType="win:Binary"/>
        // <data name="dport" inType="win:UInt16"/>
        // <data name="sport" inType="win:UInt16"/>
        // <data name="startime" inType="win:UInt32"/>
        // <data name="endtime" inType="win:UInt32"/>
        // <data name="seqnum" inType="win:UInt32"/>
        // <data name="connid" inType="win:UInt32"/>

        let mut map: ::std::collections::HashMap<&str, crate::modern_event::types::WinInTypeItem> =
            ::std::collections::HashMap::new();

        map.insert(
            "PID",
            self.modern_event
                .read_payload_item(crate::modern_event::WinInType::UInt32, None)?,
        );
        map.insert(
            "size",
            self.modern_event
                .read_payload_item(crate::modern_event::WinInType::UInt32, None)?,
        );
        map.insert(
            "daddr",
            self.modern_event
                .read_payload_item(crate::modern_event::WinInType::Binary, Some(16))?,
        );
        map.insert(
            "saddr",
            self.modern_event
                .read_payload_item(crate::modern_event::WinInType::Binary, Some(16))?,
        );
        map.insert(
            "dport",
            self.modern_event
                .read_payload_item(crate::modern_event::WinInType::UInt16, None)?,
        );
        map.insert(
            "sport",
            self.modern_event
                .read_payload_item(crate::modern_event::WinInType::UInt16, None)?,
        );
        map.insert(
            "startime",
            self.modern_event
                .read_payload_item(crate::modern_event::WinInType::UInt32, None)?,
        );
        map.insert(
            "endtime",
            self.modern_event
                .read_payload_item(crate::modern_event::WinInType::UInt32, None)?,
        );
        map.insert(
            "seqnum",
            self.modern_event
                .read_payload_item(crate::modern_event::WinInType::UInt32, None)?,
        );
        map.insert(
            "connid",
            self.modern_event
                .read_payload_item(crate::modern_event::WinInType::UInt32, None)?,
        );

        self.payload = Some(map);
        Ok(())
    }
    fn datareceived_27_args(&mut self) -> Result<(), ModernEventError> {
        // <data name="PID" inType="win:UInt32"/>
        // <data name="size" inType="win:UInt32"/>
        // <data name="daddr" inType="win:Binary"/>
        // <data name="saddr" inType="win:Binary"/>
        // <data name="dport" inType="win:UInt16"/>
        // <data name="sport" inType="win:UInt16"/>
        // <data name="seqnum" inType="win:UInt32"/>
        // <data name="connid" inType="win:UInt32"/>

        let mut map: ::std::collections::HashMap<&str, crate::modern_event::types::WinInTypeItem> =
            ::std::collections::HashMap::new();

        map.insert(
            "PID",
            self.modern_event
                .read_payload_item(crate::modern_event::WinInType::UInt32, None)?,
        );
        map.insert(
            "size",
            self.modern_event
                .read_payload_item(crate::modern_event::WinInType::UInt32, None)?,
        );
        map.insert(
            "daddr",
            self.modern_event
                .read_payload_item(crate::modern_event::WinInType::Binary, Some(16))?,
        );
        map.insert(
            "saddr",
            self.modern_event
                .read_payload_item(crate::modern_event::WinInType::Binary, Some(16))?,
        );
        map.insert(
            "dport",
            self.modern_event
                .read_payload_item(crate::modern_event::WinInType::UInt16, None)?,
        );
        map.insert(
            "sport",
            self.modern_event
                .read_payload_item(crate::modern_event::WinInType::UInt16, None)?,
        );
        map.insert(
            "seqnum",
            self.modern_event
                .read_payload_item(crate::modern_event::WinInType::UInt32, None)?,
        );
        map.insert(
            "connid",
            self.modern_event
                .read_payload_item(crate::modern_event::WinInType::UInt32, None)?,
        );

        self.payload = Some(map);
        Ok(())
    }
    fn connectionattempted_28_args(&mut self) -> Result<(), ModernEventError> {
        // <data name="PID" inType="win:UInt32"/>
        // <data name="size" inType="win:UInt32"/>
        // <data name="daddr" inType="win:Binary"/>
        // <data name="saddr" inType="win:Binary"/>
        // <data name="dport" inType="win:UInt16"/>
        // <data name="sport" inType="win:UInt16"/>
        // <data name="mss" inType="win:UInt16"/>
        // <data name="sackopt" inType="win:UInt16"/>
        // <data name="tsopt" inType="win:UInt16"/>
        // <data name="wsopt" inType="win:UInt16"/>
        // <data name="rcvwin" inType="win:UInt32"/>
        // <data name="rcvwinscale" inType="win:UInt16"/>
        // <data name="sndwinscale" inType="win:UInt16"/>
        // <data name="seqnum" inType="win:UInt32"/>
        // <data name="connid" inType="win:UInt32"/>

        let mut map: ::std::collections::HashMap<&str, crate::modern_event::types::WinInTypeItem> =
            ::std::collections::HashMap::new();

        map.insert(
            "PID",
            self.modern_event
                .read_payload_item(crate::modern_event::WinInType::UInt32, None)?,
        );
        map.insert(
            "size",
            self.modern_event
                .read_payload_item(crate::modern_event::WinInType::UInt32, None)?,
        );
        map.insert(
            "daddr",
            self.modern_event
                .read_payload_item(crate::modern_event::WinInType::Binary, Some(16))?,
        );
        map.insert(
            "saddr",
            self.modern_event
                .read_payload_item(crate::modern_event::WinInType::Binary, Some(16))?,
        );
        map.insert(
            "dport",
            self.modern_event
                .read_payload_item(crate::modern_event::WinInType::UInt16, None)?,
        );
        map.insert(
            "sport",
            self.modern_event
                .read_payload_item(crate::modern_event::WinInType::UInt16, None)?,
        );
        map.insert(
            "mss",
            self.modern_event
                .read_payload_item(crate::modern_event::WinInType::UInt16, None)?,
        );
        map.insert(
            "sackopt",
            self.modern_event
                .read_payload_item(crate::modern_event::WinInType::UInt16, None)?,
        );
        map.insert(
            "tsopt",
            self.modern_event
                .read_payload_item(crate::modern_event::WinInType::UInt16, None)?,
        );
        map.insert(
            "wsopt",
            self.modern_event
                .read_payload_item(crate::modern_event::WinInType::UInt16, None)?,
        );
        map.insert(
            "rcvwin",
            self.modern_event
                .read_payload_item(crate::modern_event::WinInType::UInt32, None)?,
        );
        map.insert(
            "rcvwinscale",
            self.modern_event
                .read_payload_item(crate::modern_event::WinInType::UInt16, None)?,
        );
        map.insert(
            "sndwinscale",
            self.modern_event
                .read_payload_item(crate::modern_event::WinInType::UInt16, None)?,
        );
        map.insert(
            "seqnum",
            self.modern_event
                .read_payload_item(crate::modern_event::WinInType::UInt32, None)?,
        );
        map.insert(
            "connid",
            self.modern_event
                .read_payload_item(crate::modern_event::WinInType::UInt32, None)?,
        );

        self.payload = Some(map);
        Ok(())
    }
}
