//! Proxy operation messages as specified in CCSDS 727.0-B-5 chapter 6.2.
use super::msg_to_user::{
    MsgToUserTlv, ReservedMessageCreationError, ReservedMessageReadError, ReservedMessageType,
    check_byte_field_width, read_single_byte_param, write_reserved_msg_header,
};
use super::{FilestoreRequestTlv, FilestoreResponseTlv, WritableTlv};
use crate::{
    ByteConversionError,
    cfdp::{
        ConditionCode, FaultHandlerCode, SegmentationControl, TransmissionMode,
        lv::Lv,
        pdu::finished::{DeliveryCode, FileStatus, pack_status_byte, unpack_status_byte},
    },
    util::UnsignedByteField,
};

/// Constructor for a proxy put request message.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct ProxyPutRequestMessageCreator<'src_lv, 'dest_lv> {
    destination_entity_id: UnsignedByteField,
    source_file_name: Lv<'src_lv>,
    dest_file_name: Lv<'dest_lv>,
}

impl<'src_lv, 'dest_lv> ProxyPutRequestMessageCreator<'src_lv, 'dest_lv> {
    /// Constructor for the proxy put message creator.
    pub fn new(
        destination_entity_id: UnsignedByteField,
        source_file_name: Lv<'src_lv>,
        dest_file_name: Lv<'dest_lv>,
    ) -> Result<Self, ReservedMessageCreationError> {
        check_byte_field_width(destination_entity_id.size())?;
        MsgToUserTlv::check_reserved_message_payload_len(Self::payload_len(
            &destination_entity_id,
            &source_file_name,
            &dest_file_name,
        ))?;
        Ok(Self {
            destination_entity_id,
            source_file_name,
            dest_file_name,
        })
    }

    /// Full written length.
    #[inline]
    pub fn len_written(&self) -> usize {
        MsgToUserTlv::full_len_for_reserved_cfdp_message(Self::payload_len(
            &self.destination_entity_id,
            &self.source_file_name,
            &self.dest_file_name,
        ))
    }

    #[inline]
    fn payload_len(
        destination_entity_id: &UnsignedByteField,
        source_file_name: &Lv,
        dest_file_name: &Lv,
    ) -> usize {
        // The destination entity ID is encoded as an LV.
        1 + destination_entity_id.size() + source_file_name.len_full() + dest_file_name.len_full()
    }

    /// Write the proxy put message into a raw byte buffer.
    ///
    /// Returns the number of bytes written into the provided buffer.
    pub fn write_to_slice(&self, buf: &mut [u8]) -> Result<usize, ByteConversionError> {
        // The payload length was checked in the constructor.
        let mut current_index = write_reserved_msg_header(
            buf,
            ReservedMessageType::ProxyPutRequest,
            Self::payload_len(
                &self.destination_entity_id,
                &self.source_file_name,
                &self.dest_file_name,
            ),
        )?;
        buf[current_index] = self.destination_entity_id.size() as u8;
        current_index += 1;
        current_index += self
            .destination_entity_id
            .write_to_slice_be(&mut buf[current_index..])?;
        current_index += self
            .source_file_name
            .write_to_slice(&mut buf[current_index..])?;
        current_index += self
            .dest_file_name
            .write_to_slice(&mut buf[current_index..])?;
        Ok(current_index)
    }

    /// Write the message to an owned [alloc::vec::Vec].
    #[cfg(feature = "alloc")]
    pub fn to_vec(&self) -> alloc::vec::Vec<u8> {
        WritableTlv::to_vec(self)
    }
}

impl WritableTlv for ProxyPutRequestMessageCreator<'_, '_> {
    fn write_to_slice(&self, buf: &mut [u8]) -> Result<usize, ByteConversionError> {
        self.write_to_slice(buf)
    }

    #[inline]
    fn len_written(&self) -> usize {
        self.len_written()
    }
}

/// Reader for a proxy put request message.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct ProxyPutRequestMessageReader<'data> {
    destination_entity_id: UnsignedByteField,
    source_file_name: Lv<'data>,
    dest_file_name: Lv<'data>,
}

impl<'data> ProxyPutRequestMessageReader<'data> {
    /// Read a proxy put request from a raw message to user TLV.
    pub fn from_bytes(buf: &'data [u8]) -> Result<Self, ReservedMessageReadError> {
        Self::try_from(MsgToUserTlv::from_bytes(buf)?)
    }

    /// Destination entity ID.
    #[inline]
    pub fn destination_entity_id(&self) -> UnsignedByteField {
        self.destination_entity_id
    }

    /// Source file name.
    #[inline]
    pub fn source_file_name(&self) -> Lv<'data> {
        self.source_file_name
    }

    /// Destination file name.
    #[inline]
    pub fn dest_file_name(&self) -> Lv<'data> {
        self.dest_file_name
    }
}

impl<'data> TryFrom<MsgToUserTlv<'data>> for ProxyPutRequestMessageReader<'data> {
    type Error = ReservedMessageReadError;

    fn try_from(msg_to_user: MsgToUserTlv<'data>) -> Result<Self, Self::Error> {
        let params = msg_to_user.reserved_msg_params(ReservedMessageType::ProxyPutRequest)?;
        let dest_id_lv = Lv::from_bytes(params)?;
        check_byte_field_width(dest_id_lv.len_value())?;
        let destination_entity_id =
            UnsignedByteField::new_from_be_bytes(dest_id_lv.len_value(), dest_id_lv.value())?;
        let mut current_index = dest_id_lv.len_full();
        let source_file_name = Lv::from_bytes(&params[current_index..])?;
        current_index += source_file_name.len_full();
        let dest_file_name = Lv::from_bytes(&params[current_index..])?;
        Ok(Self {
            destination_entity_id,
            source_file_name,
            dest_file_name,
        })
    }
}

/// Proxy put response message.
///
/// A single type is used for both creation and reading because it does not borrow any data.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ProxyPutResponseMessage {
    condition_code: ConditionCode,
    delivery_code: DeliveryCode,
    file_status: FileStatus,
}

impl ProxyPutResponseMessage {
    const PAYLOAD_LEN: usize = 1;

    /// Constructor for the proxy put response message.
    pub fn new(
        condition_code: ConditionCode,
        delivery_code: DeliveryCode,
        file_status: FileStatus,
    ) -> Self {
        Self {
            condition_code,
            delivery_code,
            file_status,
        }
    }

    /// Read a proxy put response from a raw message to user TLV.
    pub fn from_bytes(buf: &[u8]) -> Result<Self, ReservedMessageReadError> {
        Self::try_from(MsgToUserTlv::from_bytes(buf)?)
    }

    /// Condition code.
    #[inline]
    pub fn condition_code(&self) -> ConditionCode {
        self.condition_code
    }

    /// Delivery code.
    #[inline]
    pub fn delivery_code(&self) -> DeliveryCode {
        self.delivery_code
    }

    /// File status.
    #[inline]
    pub fn file_status(&self) -> FileStatus {
        self.file_status
    }

    /// Full written length.
    #[inline]
    pub fn len_written(&self) -> usize {
        MsgToUserTlv::full_len_for_reserved_cfdp_message(Self::PAYLOAD_LEN)
    }

    /// Write the proxy put response message into a raw byte buffer.
    ///
    /// Returns the number of bytes written into the provided buffer.
    pub fn write_to_slice(&self, buf: &mut [u8]) -> Result<usize, ByteConversionError> {
        let current_index = write_reserved_msg_header(
            buf,
            ReservedMessageType::ProxyPutResponse,
            Self::PAYLOAD_LEN,
        )?;
        buf[current_index] =
            pack_status_byte(self.condition_code, self.delivery_code, self.file_status);
        Ok(current_index + Self::PAYLOAD_LEN)
    }

    /// Write the message to an owned [alloc::vec::Vec].
    #[cfg(feature = "alloc")]
    pub fn to_vec(&self) -> alloc::vec::Vec<u8> {
        WritableTlv::to_vec(self)
    }
}

impl TryFrom<MsgToUserTlv<'_>> for ProxyPutResponseMessage {
    type Error = ReservedMessageReadError;

    fn try_from(msg_to_user: MsgToUserTlv<'_>) -> Result<Self, Self::Error> {
        let params = msg_to_user.reserved_msg_params(ReservedMessageType::ProxyPutResponse)?;
        let status = read_single_byte_param(params)?;
        let (condition_code, delivery_code, file_status) =
            unpack_status_byte(status).map_err(ReservedMessageReadError::InvalidConditionCode)?;
        Ok(Self {
            condition_code,
            delivery_code,
            file_status,
        })
    }
}

impl WritableTlv for ProxyPutResponseMessage {
    fn write_to_slice(&self, buf: &mut [u8]) -> Result<usize, ByteConversionError> {
        self.write_to_slice(buf)
    }

    #[inline]
    fn len_written(&self) -> usize {
        self.len_written()
    }
}

/// Proxy transmission mode message.
///
/// Overrides the transmission mode of a proxy put request sent along with it.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ProxyTransmissionModeMessage {
    transmission_mode: TransmissionMode,
}

impl ProxyTransmissionModeMessage {
    const PAYLOAD_LEN: usize = 1;

    /// Constructor for the proxy transmission mode message.
    pub fn new(transmission_mode: TransmissionMode) -> Self {
        Self { transmission_mode }
    }

    /// Read a proxy transmission mode message from a raw message to user TLV.
    pub fn from_bytes(buf: &[u8]) -> Result<Self, ReservedMessageReadError> {
        Self::try_from(MsgToUserTlv::from_bytes(buf)?)
    }

    /// Transmission mode.
    #[inline]
    pub fn transmission_mode(&self) -> TransmissionMode {
        self.transmission_mode
    }

    /// Full written length.
    #[inline]
    pub fn len_written(&self) -> usize {
        MsgToUserTlv::full_len_for_reserved_cfdp_message(Self::PAYLOAD_LEN)
    }

    /// Write the proxy transmission mode message into a raw byte buffer.
    ///
    /// Returns the number of bytes written into the provided buffer.
    pub fn write_to_slice(&self, buf: &mut [u8]) -> Result<usize, ByteConversionError> {
        let current_index = write_reserved_msg_header(
            buf,
            ReservedMessageType::ProxyTransmissionMode,
            Self::PAYLOAD_LEN,
        )?;
        // 7 spare bits set to 0, followed by the transmission mode bit.
        buf[current_index] = self.transmission_mode as u8;
        Ok(current_index + Self::PAYLOAD_LEN)
    }

    /// Write the message to an owned [alloc::vec::Vec].
    #[cfg(feature = "alloc")]
    pub fn to_vec(&self) -> alloc::vec::Vec<u8> {
        WritableTlv::to_vec(self)
    }
}

impl TryFrom<MsgToUserTlv<'_>> for ProxyTransmissionModeMessage {
    type Error = ReservedMessageReadError;

    fn try_from(msg_to_user: MsgToUserTlv<'_>) -> Result<Self, Self::Error> {
        let params = msg_to_user.reserved_msg_params(ReservedMessageType::ProxyTransmissionMode)?;
        let param = read_single_byte_param(params)?;
        // A single bit covers the full value range, so the conversion can not fail.
        let transmission_mode = TransmissionMode::try_from(param & 0b1).unwrap();
        Ok(Self { transmission_mode })
    }
}

impl WritableTlv for ProxyTransmissionModeMessage {
    fn write_to_slice(&self, buf: &mut [u8]) -> Result<usize, ByteConversionError> {
        self.write_to_slice(buf)
    }

    #[inline]
    fn len_written(&self) -> usize {
        self.len_written()
    }
}

/// Proxy closure request message.
///
/// Overrides the closure requested flag of a proxy put request sent along with it.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ProxyClosureRequestMessage {
    closure_requested: bool,
}

impl ProxyClosureRequestMessage {
    const PAYLOAD_LEN: usize = 1;

    /// Constructor for the proxy closure request message.
    pub fn new(closure_requested: bool) -> Self {
        Self { closure_requested }
    }

    /// Read a proxy closure request message from a raw message to user TLV.
    pub fn from_bytes(buf: &[u8]) -> Result<Self, ReservedMessageReadError> {
        Self::try_from(MsgToUserTlv::from_bytes(buf)?)
    }

    /// Closure requested flag.
    #[inline]
    pub fn closure_requested(&self) -> bool {
        self.closure_requested
    }

    /// Full written length.
    #[inline]
    pub fn len_written(&self) -> usize {
        MsgToUserTlv::full_len_for_reserved_cfdp_message(Self::PAYLOAD_LEN)
    }

    /// Write the proxy closure request message into a raw byte buffer.
    ///
    /// Returns the number of bytes written into the provided buffer.
    pub fn write_to_slice(&self, buf: &mut [u8]) -> Result<usize, ByteConversionError> {
        let current_index = write_reserved_msg_header(
            buf,
            ReservedMessageType::ProxyClosureRequest,
            Self::PAYLOAD_LEN,
        )?;
        // 7 spare bits set to 0, followed by the closure requested bit.
        buf[current_index] = self.closure_requested as u8;
        Ok(current_index + Self::PAYLOAD_LEN)
    }

    /// Write the message to an owned [alloc::vec::Vec].
    #[cfg(feature = "alloc")]
    pub fn to_vec(&self) -> alloc::vec::Vec<u8> {
        WritableTlv::to_vec(self)
    }
}

impl TryFrom<MsgToUserTlv<'_>> for ProxyClosureRequestMessage {
    type Error = ReservedMessageReadError;

    fn try_from(msg_to_user: MsgToUserTlv<'_>) -> Result<Self, Self::Error> {
        let params = msg_to_user.reserved_msg_params(ReservedMessageType::ProxyClosureRequest)?;
        let param = read_single_byte_param(params)?;
        Ok(Self {
            closure_requested: param & 0b1 == 1,
        })
    }
}

impl WritableTlv for ProxyClosureRequestMessage {
    fn write_to_slice(&self, buf: &mut [u8]) -> Result<usize, ByteConversionError> {
        self.write_to_slice(buf)
    }

    #[inline]
    fn len_written(&self) -> usize {
        self.len_written()
    }
}

/// Proxy put cancel message.
///
/// Cancels a proxy put operation. The message has no parameters.
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ProxyPutCancelMessage;

impl ProxyPutCancelMessage {
    const PAYLOAD_LEN: usize = 0;

    /// Read a proxy put cancel message from a raw message to user TLV.
    pub fn from_bytes(buf: &[u8]) -> Result<Self, ReservedMessageReadError> {
        Self::try_from(MsgToUserTlv::from_bytes(buf)?)
    }

    /// Full written length.
    #[inline]
    pub fn len_written(&self) -> usize {
        MsgToUserTlv::full_len_for_reserved_cfdp_message(Self::PAYLOAD_LEN)
    }

    /// Write the proxy put cancel message into a raw byte buffer.
    ///
    /// Returns the number of bytes written into the provided buffer.
    pub fn write_to_slice(&self, buf: &mut [u8]) -> Result<usize, ByteConversionError> {
        write_reserved_msg_header(buf, ReservedMessageType::ProxyPutCancel, Self::PAYLOAD_LEN)
    }

    /// Write the message to an owned [alloc::vec::Vec].
    #[cfg(feature = "alloc")]
    pub fn to_vec(&self) -> alloc::vec::Vec<u8> {
        WritableTlv::to_vec(self)
    }
}

impl TryFrom<MsgToUserTlv<'_>> for ProxyPutCancelMessage {
    type Error = ReservedMessageReadError;

    fn try_from(msg_to_user: MsgToUserTlv<'_>) -> Result<Self, Self::Error> {
        msg_to_user.reserved_msg_params(ReservedMessageType::ProxyPutCancel)?;
        Ok(Self)
    }
}

impl WritableTlv for ProxyPutCancelMessage {
    fn write_to_slice(&self, buf: &mut [u8]) -> Result<usize, ByteConversionError> {
        self.write_to_slice(buf)
    }

    #[inline]
    fn len_written(&self) -> usize {
        self.len_written()
    }
}

/// Writes a reserved message which only has a single LV parameter.
fn write_lv_param_msg(
    buf: &mut [u8],
    msg_type: ReservedMessageType,
    lv: &Lv,
) -> Result<usize, ByteConversionError> {
    let current_index = write_reserved_msg_header(buf, msg_type, lv.len_full())?;
    Ok(current_index + lv.write_to_slice(&mut buf[current_index..])?)
}

/// Proxy message to user message.
///
/// The message text is the value of a message to user which the respondent forwards along
/// with the proxy put request.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ProxyMessageToUserMessage<'data> {
    message: Lv<'data>,
}

impl<'data> ProxyMessageToUserMessage<'data> {
    /// Constructor for the proxy message to user message.
    pub fn new(message_text: Lv<'data>) -> Result<Self, ReservedMessageCreationError> {
        MsgToUserTlv::check_reserved_message_payload_len(message_text.len_full())?;
        Ok(Self {
            message: message_text,
        })
    }

    /// Read a proxy message to user message from a raw message to user TLV.
    pub fn from_bytes(buf: &'data [u8]) -> Result<Self, ReservedMessageReadError> {
        Self::try_from(MsgToUserTlv::from_bytes(buf)?)
    }

    /// Message text.
    #[inline]
    pub fn message_text(&self) -> Lv<'data> {
        self.message
    }

    /// Message to user TLV which should be forwarded by the respondent.
    pub fn to_msg_to_user(&self) -> MsgToUserTlv<'data> {
        // An LV value always fits into a TLV value.
        MsgToUserTlv::new(self.message.value()).unwrap()
    }

    /// Full written length.
    #[inline]
    pub fn len_written(&self) -> usize {
        MsgToUserTlv::full_len_for_reserved_cfdp_message(self.message.len_full())
    }

    /// Write the proxy message to user message into a raw byte buffer.
    ///
    /// Returns the number of bytes written into the provided buffer.
    pub fn write_to_slice(&self, buf: &mut [u8]) -> Result<usize, ByteConversionError> {
        write_lv_param_msg(buf, ReservedMessageType::ProxyMessageToUser, &self.message)
    }

    /// Write the message to an owned [alloc::vec::Vec].
    #[cfg(feature = "alloc")]
    pub fn to_vec(&self) -> alloc::vec::Vec<u8> {
        WritableTlv::to_vec(self)
    }
}

impl<'data> TryFrom<MsgToUserTlv<'data>> for ProxyMessageToUserMessage<'data> {
    type Error = ReservedMessageReadError;

    fn try_from(msg_to_user: MsgToUserTlv<'data>) -> Result<Self, Self::Error> {
        let params = msg_to_user.reserved_msg_params(ReservedMessageType::ProxyMessageToUser)?;
        Ok(Self {
            message: Lv::from_bytes(params)?,
        })
    }
}

impl WritableTlv for ProxyMessageToUserMessage<'_> {
    fn write_to_slice(&self, buf: &mut [u8]) -> Result<usize, ByteConversionError> {
        self.write_to_slice(buf)
    }

    #[inline]
    fn len_written(&self) -> usize {
        self.len_written()
    }
}

/// Proxy filestore request message.
///
/// Contains a filestore request which the respondent forwards along with the proxy put
/// request.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct ProxyFilestoreRequestMessage<'first_name, 'second_name> {
    request: FilestoreRequestTlv<'first_name, 'second_name>,
}

impl<'first_name, 'second_name> ProxyFilestoreRequestMessage<'first_name, 'second_name> {
    /// Constructor for the proxy filestore request message.
    pub fn new(
        request: FilestoreRequestTlv<'first_name, 'second_name>,
    ) -> Result<Self, ReservedMessageCreationError> {
        MsgToUserTlv::check_reserved_message_payload_len(Self::payload_len(&request))?;
        Ok(Self { request })
    }

    /// Filestore request.
    #[inline]
    pub fn request(&self) -> FilestoreRequestTlv<'first_name, 'second_name> {
        self.request
    }

    #[inline]
    fn payload_len(request: &FilestoreRequestTlv) -> usize {
        // The request is encoded as an LV.
        1 + request.len_value()
    }

    /// Full written length.
    #[inline]
    pub fn len_written(&self) -> usize {
        MsgToUserTlv::full_len_for_reserved_cfdp_message(Self::payload_len(&self.request))
    }

    /// Write the proxy filestore request message into a raw byte buffer.
    ///
    /// Returns the number of bytes written into the provided buffer.
    pub fn write_to_slice(&self, buf: &mut [u8]) -> Result<usize, ByteConversionError> {
        let mut current_index = write_reserved_msg_header(
            buf,
            ReservedMessageType::ProxyFilestoreRequest,
            Self::payload_len(&self.request),
        )?;
        buf[current_index] = self.request.len_value() as u8;
        current_index += 1;
        current_index += self
            .request
            .write_value_no_len_check(&mut buf[current_index..]);
        Ok(current_index)
    }

    /// Write the message to an owned [alloc::vec::Vec].
    #[cfg(feature = "alloc")]
    pub fn to_vec(&self) -> alloc::vec::Vec<u8> {
        WritableTlv::to_vec(self)
    }
}

impl<'data> ProxyFilestoreRequestMessage<'data, 'data> {
    /// Read a proxy filestore request message from a raw message to user TLV.
    pub fn from_bytes(buf: &'data [u8]) -> Result<Self, ReservedMessageReadError> {
        Self::try_from(MsgToUserTlv::from_bytes(buf)?)
    }
}

impl<'data> TryFrom<MsgToUserTlv<'data>> for ProxyFilestoreRequestMessage<'data, 'data> {
    type Error = ReservedMessageReadError;

    fn try_from(msg_to_user: MsgToUserTlv<'data>) -> Result<Self, Self::Error> {
        let params = msg_to_user.reserved_msg_params(ReservedMessageType::ProxyFilestoreRequest)?;
        let request_lv = Lv::from_bytes(params)?;
        Ok(Self {
            request: FilestoreRequestTlv::from_value(request_lv.value())?,
        })
    }
}

impl WritableTlv for ProxyFilestoreRequestMessage<'_, '_> {
    fn write_to_slice(&self, buf: &mut [u8]) -> Result<usize, ByteConversionError> {
        self.write_to_slice(buf)
    }

    #[inline]
    fn len_written(&self) -> usize {
        self.len_written()
    }
}

/// Proxy fault handler override message.
///
/// Contains a fault handler override which the respondent forwards along with the proxy put
/// request.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ProxyFaultHandlerOverrideMessage {
    condition_code: ConditionCode,
    handler_code: FaultHandlerCode,
}

impl ProxyFaultHandlerOverrideMessage {
    const PAYLOAD_LEN: usize = 1;

    /// Constructor for the proxy fault handler override message.
    pub fn new(condition_code: ConditionCode, handler_code: FaultHandlerCode) -> Self {
        Self {
            condition_code,
            handler_code,
        }
    }

    /// Read a proxy fault handler override message from a raw message to user TLV.
    pub fn from_bytes(buf: &[u8]) -> Result<Self, ReservedMessageReadError> {
        Self::try_from(MsgToUserTlv::from_bytes(buf)?)
    }

    /// Condition code for which the fault handler is overridden.
    #[inline]
    pub fn condition_code(&self) -> ConditionCode {
        self.condition_code
    }

    /// Fault handler code.
    #[inline]
    pub fn handler_code(&self) -> FaultHandlerCode {
        self.handler_code
    }

    /// Full written length.
    #[inline]
    pub fn len_written(&self) -> usize {
        MsgToUserTlv::full_len_for_reserved_cfdp_message(Self::PAYLOAD_LEN)
    }

    /// Write the proxy fault handler override message into a raw byte buffer.
    ///
    /// Returns the number of bytes written into the provided buffer.
    pub fn write_to_slice(&self, buf: &mut [u8]) -> Result<usize, ByteConversionError> {
        let current_index = write_reserved_msg_header(
            buf,
            ReservedMessageType::ProxyFaultHandlerOverride,
            Self::PAYLOAD_LEN,
        )?;
        buf[current_index] = ((self.condition_code as u8) << 4) | self.handler_code as u8;
        Ok(current_index + Self::PAYLOAD_LEN)
    }

    /// Write the message to an owned [alloc::vec::Vec].
    #[cfg(feature = "alloc")]
    pub fn to_vec(&self) -> alloc::vec::Vec<u8> {
        WritableTlv::to_vec(self)
    }
}

impl TryFrom<MsgToUserTlv<'_>> for ProxyFaultHandlerOverrideMessage {
    type Error = ReservedMessageReadError;

    fn try_from(msg_to_user: MsgToUserTlv<'_>) -> Result<Self, Self::Error> {
        let params =
            msg_to_user.reserved_msg_params(ReservedMessageType::ProxyFaultHandlerOverride)?;
        let param = read_single_byte_param(params)?;
        let raw_condition_code = param >> 4;
        let raw_handler_code = param & 0b1111;
        Ok(Self {
            condition_code: ConditionCode::try_from(raw_condition_code)
                .map_err(|_| ReservedMessageReadError::InvalidConditionCode(raw_condition_code))?,
            handler_code: FaultHandlerCode::try_from(raw_handler_code)
                .map_err(|_| ReservedMessageReadError::InvalidFaultHandlerCode(raw_handler_code))?,
        })
    }
}

impl WritableTlv for ProxyFaultHandlerOverrideMessage {
    fn write_to_slice(&self, buf: &mut [u8]) -> Result<usize, ByteConversionError> {
        self.write_to_slice(buf)
    }

    #[inline]
    fn len_written(&self) -> usize {
        self.len_written()
    }
}

/// Proxy flow label message.
///
/// Overrides the flow label of a proxy put request sent along with it.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ProxyFlowLabelMessage<'data> {
    flow_label: Lv<'data>,
}

impl<'data> ProxyFlowLabelMessage<'data> {
    /// Constructor for the proxy flow label message.
    pub fn new(flow_label: Lv<'data>) -> Result<Self, ReservedMessageCreationError> {
        MsgToUserTlv::check_reserved_message_payload_len(flow_label.len_full())?;
        Ok(Self { flow_label })
    }

    /// Read a proxy flow label message from a raw message to user TLV.
    pub fn from_bytes(buf: &'data [u8]) -> Result<Self, ReservedMessageReadError> {
        Self::try_from(MsgToUserTlv::from_bytes(buf)?)
    }

    /// Flow label.
    #[inline]
    pub fn flow_label(&self) -> Lv<'data> {
        self.flow_label
    }

    /// Full written length.
    #[inline]
    pub fn len_written(&self) -> usize {
        MsgToUserTlv::full_len_for_reserved_cfdp_message(self.flow_label.len_full())
    }

    /// Write the proxy flow label message into a raw byte buffer.
    ///
    /// Returns the number of bytes written into the provided buffer.
    pub fn write_to_slice(&self, buf: &mut [u8]) -> Result<usize, ByteConversionError> {
        write_lv_param_msg(buf, ReservedMessageType::ProxyFlowLabel, &self.flow_label)
    }

    /// Write the message to an owned [alloc::vec::Vec].
    #[cfg(feature = "alloc")]
    pub fn to_vec(&self) -> alloc::vec::Vec<u8> {
        WritableTlv::to_vec(self)
    }
}

impl<'data> TryFrom<MsgToUserTlv<'data>> for ProxyFlowLabelMessage<'data> {
    type Error = ReservedMessageReadError;

    fn try_from(msg_to_user: MsgToUserTlv<'data>) -> Result<Self, Self::Error> {
        let params = msg_to_user.reserved_msg_params(ReservedMessageType::ProxyFlowLabel)?;
        Ok(Self {
            flow_label: Lv::from_bytes(params)?,
        })
    }
}

impl WritableTlv for ProxyFlowLabelMessage<'_> {
    fn write_to_slice(&self, buf: &mut [u8]) -> Result<usize, ByteConversionError> {
        self.write_to_slice(buf)
    }

    #[inline]
    fn len_written(&self) -> usize {
        self.len_written()
    }
}

/// Proxy segmentation control message.
///
/// Overrides the segmentation control of a proxy put request sent along with it.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ProxySegmentationControlMessage {
    segmentation_control: SegmentationControl,
}

impl ProxySegmentationControlMessage {
    const PAYLOAD_LEN: usize = 1;

    /// Constructor for the proxy segmentation control message.
    pub fn new(segmentation_control: SegmentationControl) -> Self {
        Self {
            segmentation_control,
        }
    }

    /// Read a proxy segmentation control message from a raw message to user TLV.
    pub fn from_bytes(buf: &[u8]) -> Result<Self, ReservedMessageReadError> {
        Self::try_from(MsgToUserTlv::from_bytes(buf)?)
    }

    /// Segmentation control.
    #[inline]
    pub fn segmentation_control(&self) -> SegmentationControl {
        self.segmentation_control
    }

    /// Full written length.
    #[inline]
    pub fn len_written(&self) -> usize {
        MsgToUserTlv::full_len_for_reserved_cfdp_message(Self::PAYLOAD_LEN)
    }

    /// Write the proxy segmentation control message into a raw byte buffer.
    ///
    /// Returns the number of bytes written into the provided buffer.
    pub fn write_to_slice(&self, buf: &mut [u8]) -> Result<usize, ByteConversionError> {
        let current_index = write_reserved_msg_header(
            buf,
            ReservedMessageType::ProxySegmentationControl,
            Self::PAYLOAD_LEN,
        )?;
        // 7 spare bits set to 0, followed by the segmentation control bit. Table 6-10 of the
        // standard inverts the bit compared to the PDU header: 0 means record boundaries are
        // respected.
        buf[current_index] = match self.segmentation_control {
            SegmentationControl::WithRecordBoundaryPreservation => 0,
            SegmentationControl::NoRecordBoundaryPreservation => 1,
        };
        Ok(current_index + Self::PAYLOAD_LEN)
    }

    /// Write the message to an owned [alloc::vec::Vec].
    #[cfg(feature = "alloc")]
    pub fn to_vec(&self) -> alloc::vec::Vec<u8> {
        WritableTlv::to_vec(self)
    }
}

impl TryFrom<MsgToUserTlv<'_>> for ProxySegmentationControlMessage {
    type Error = ReservedMessageReadError;

    fn try_from(msg_to_user: MsgToUserTlv<'_>) -> Result<Self, Self::Error> {
        let params =
            msg_to_user.reserved_msg_params(ReservedMessageType::ProxySegmentationControl)?;
        let param = read_single_byte_param(params)?;
        let segmentation_control = if param & 0b1 == 0 {
            SegmentationControl::WithRecordBoundaryPreservation
        } else {
            SegmentationControl::NoRecordBoundaryPreservation
        };
        Ok(Self {
            segmentation_control,
        })
    }
}

impl WritableTlv for ProxySegmentationControlMessage {
    fn write_to_slice(&self, buf: &mut [u8]) -> Result<usize, ByteConversionError> {
        self.write_to_slice(buf)
    }

    #[inline]
    fn len_written(&self) -> usize {
        self.len_written()
    }
}

/// Proxy filestore response message.
///
/// Reports one filestore response of the transaction which was triggered by a proxy put
/// request.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ProxyFilestoreResponseMessage<'first_name, 'second_name, 'fs_msg> {
    response: FilestoreResponseTlv<'first_name, 'second_name, 'fs_msg>,
}

impl<'first_name, 'second_name, 'fs_msg>
    ProxyFilestoreResponseMessage<'first_name, 'second_name, 'fs_msg>
{
    /// Constructor for the proxy filestore response message.
    pub fn new(
        response: FilestoreResponseTlv<'first_name, 'second_name, 'fs_msg>,
    ) -> Result<Self, ReservedMessageCreationError> {
        MsgToUserTlv::check_reserved_message_payload_len(Self::payload_len(&response))?;
        Ok(Self { response })
    }

    /// Filestore response.
    #[inline]
    pub fn response(&self) -> FilestoreResponseTlv<'first_name, 'second_name, 'fs_msg> {
        self.response
    }

    #[inline]
    fn payload_len(response: &FilestoreResponseTlv) -> usize {
        // The response is encoded as an LV.
        1 + response.len_value()
    }

    /// Full written length.
    #[inline]
    pub fn len_written(&self) -> usize {
        MsgToUserTlv::full_len_for_reserved_cfdp_message(Self::payload_len(&self.response))
    }

    /// Write the proxy filestore response message into a raw byte buffer.
    ///
    /// Returns the number of bytes written into the provided buffer.
    pub fn write_to_slice(&self, buf: &mut [u8]) -> Result<usize, ByteConversionError> {
        let mut current_index = write_reserved_msg_header(
            buf,
            ReservedMessageType::ProxyFilestoreResponse,
            Self::payload_len(&self.response),
        )?;
        buf[current_index] = self.response.len_value() as u8;
        current_index += 1;
        current_index += self
            .response
            .write_value_no_len_check(&mut buf[current_index..]);
        Ok(current_index)
    }

    /// Write the message to an owned [alloc::vec::Vec].
    #[cfg(feature = "alloc")]
    pub fn to_vec(&self) -> alloc::vec::Vec<u8> {
        WritableTlv::to_vec(self)
    }
}

impl<'data> ProxyFilestoreResponseMessage<'data, 'data, 'data> {
    /// Read a proxy filestore response message from a raw message to user TLV.
    pub fn from_bytes(buf: &'data [u8]) -> Result<Self, ReservedMessageReadError> {
        Self::try_from(MsgToUserTlv::from_bytes(buf)?)
    }
}

impl<'data> TryFrom<MsgToUserTlv<'data>> for ProxyFilestoreResponseMessage<'data, 'data, 'data> {
    type Error = ReservedMessageReadError;

    fn try_from(msg_to_user: MsgToUserTlv<'data>) -> Result<Self, Self::Error> {
        let params =
            msg_to_user.reserved_msg_params(ReservedMessageType::ProxyFilestoreResponse)?;
        let response_lv = Lv::from_bytes(params)?;
        Ok(Self {
            response: FilestoreResponseTlv::from_value(response_lv.value())?,
        })
    }
}

impl WritableTlv for ProxyFilestoreResponseMessage<'_, '_, '_> {
    fn write_to_slice(&self, buf: &mut [u8]) -> Result<usize, ByteConversionError> {
        self.write_to_slice(buf)
    }

    #[inline]
    fn len_written(&self) -> usize {
        self.len_written()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cfdp::{
        TlvLvDataTooLargeError, TlvLvError,
        tlv::{FilestoreActionCode, TlvType},
    };
    use crate::util::UnsignedByteFieldError;

    fn proxy_put_request_creator() -> ProxyPutRequestMessageCreator<'static, 'static> {
        ProxyPutRequestMessageCreator::new(
            UnsignedByteField::new(2, 0x0102),
            Lv::try_from("src.txt").unwrap(),
            Lv::try_from("dest.txt").unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn test_proxy_put_request_serialization() {
        let creator = proxy_put_request_creator();
        let mut buf: [u8; 64] = [0; 64];
        let written = creator.write_to_slice(&mut buf).unwrap();
        assert_eq!(written, creator.len_written());
        assert_eq!(written, 2 + 4 + 1 + 3 + 8 + 9);
        assert_eq!(buf[0], TlvType::MsgToUser as u8);
        assert_eq!(buf[1] as usize, written - 2);
        assert_eq!(&buf[2..6], b"cfdp");
        assert_eq!(buf[6], ReservedMessageType::ProxyPutRequest as u8);
        assert_eq!(&buf[7..10], &[2, 0x01, 0x02]);
        assert_eq!(buf[10], 7);
        assert_eq!(&buf[11..18], b"src.txt");
        assert_eq!(buf[18], 8);
        assert_eq!(&buf[19..27], b"dest.txt");
    }

    #[test]
    fn test_proxy_put_request_too_large() {
        // Each file name fits into an LV, but both together exceed the TLV value field.
        let file_name = [b'a'; 125];
        let file_name = core::str::from_utf8(&file_name).unwrap();
        let entity_id = UnsignedByteField::new(2, 0x0102);
        let src_name = Lv::try_from(file_name).unwrap();
        let dest_name = Lv::try_from(file_name).unwrap();
        // Message ID, message type, entity ID LV and two file name LVs.
        let expected_len = 4 + 1 + 3 + 126 + 126;
        assert!(expected_len > u8::MAX as usize);
        assert_eq!(
            ProxyPutRequestMessageCreator::new(entity_id, src_name, dest_name).unwrap_err(),
            ReservedMessageCreationError::DataTooLarge(TlvLvDataTooLargeError(expected_len))
        );
        // A 120 byte destination name brings the value field to exactly 255 bytes.
        let shorter_name = Lv::try_from(&file_name[..120]).unwrap();
        let creator =
            ProxyPutRequestMessageCreator::new(entity_id, src_name, shorter_name).unwrap();
        assert_eq!(creator.len_written(), 2 + u8::MAX as usize);
    }

    #[test]
    fn test_proxy_put_request_invalid_entity_id_width() {
        for width in [0, 3, 5, 6, 7, 9] {
            assert_eq!(
                ProxyPutRequestMessageCreator::new(
                    UnsignedByteField::new(width, 0),
                    Lv::try_from("src.txt").unwrap(),
                    Lv::try_from("dest.txt").unwrap(),
                ),
                Err(ReservedMessageCreationError::InvalidEntityId(
                    UnsignedByteFieldError::InvalidWidth {
                        found: width,
                        expected: None
                    }
                ))
            );
        }
    }

    #[test]
    fn test_proxy_put_request_reader_invalid_entity_id_width() {
        // Empty entity ID followed by two empty file names.
        let msg_to_user = MsgToUserTlv::new(b"cfdp\x00\x00\x00\x00").unwrap();
        assert_eq!(
            ProxyPutRequestMessageReader::try_from(msg_to_user),
            Err(ReservedMessageReadError::InvalidEntityId(
                UnsignedByteFieldError::InvalidWidth {
                    found: 0,
                    expected: None
                }
            ))
        );
        // 3 byte entity ID.
        let msg_to_user = MsgToUserTlv::new(b"cfdp\x00\x03\x01\x02\x03\x00\x00").unwrap();
        assert_eq!(
            ProxyPutRequestMessageReader::try_from(msg_to_user),
            Err(ReservedMessageReadError::InvalidEntityId(
                UnsignedByteFieldError::InvalidWidth {
                    found: 3,
                    expected: None
                }
            ))
        );
    }

    #[test]
    fn test_proxy_put_request_buf_too_small() {
        let creator = proxy_put_request_creator();
        let mut buf: [u8; 8] = [0; 8];
        assert_eq!(
            creator.write_to_slice(&mut buf),
            Err(ByteConversionError::ToSliceTooSmall {
                found: 8,
                expected: creator.len_written()
            })
        );
    }

    #[test]
    fn test_proxy_put_request_round_trip() {
        let creator = proxy_put_request_creator();
        let mut buf: [u8; 64] = [0; 64];
        let written = creator.write_to_slice(&mut buf).unwrap();
        let msg_to_user = MsgToUserTlv::from_bytes(&buf[..written]).unwrap();
        assert_eq!(
            msg_to_user.reserved_cfdp_msg_type(),
            Some(Ok(ReservedMessageType::ProxyPutRequest))
        );
        let reader = ProxyPutRequestMessageReader::try_from(msg_to_user).unwrap();
        assert_eq!(
            reader.destination_entity_id(),
            UnsignedByteField::new(2, 0x0102)
        );
        assert_eq!(
            reader.source_file_name().value_as_str(),
            Some(Ok("src.txt"))
        );
        assert_eq!(reader.dest_file_name().value_as_str(), Some(Ok("dest.txt")));
        assert_eq!(
            ProxyPutRequestMessageReader::from_bytes(&buf[..written]).unwrap(),
            reader
        );
    }

    #[test]
    fn test_proxy_put_request_reader_wrong_type() {
        let msg_to_user = MsgToUserTlv::new(b"cfdp\x09").unwrap();
        assert_eq!(
            ProxyPutRequestMessageReader::try_from(msg_to_user),
            Err(ReservedMessageReadError::UnexpectedMessageType {
                found: ReservedMessageType::ProxyPutCancel,
                expected: ReservedMessageType::ProxyPutRequest,
            })
        );
    }

    #[test]
    fn test_proxy_put_request_reader_not_reserved() {
        let msg_to_user = MsgToUserTlv::new(&[1, 2, 3]).unwrap();
        assert_eq!(
            ProxyPutRequestMessageReader::try_from(msg_to_user),
            Err(ReservedMessageReadError::NotReservedMessage)
        );
    }

    #[test]
    fn test_proxy_put_request_reader_truncated() {
        // Destination entity ID LV announces 2 bytes, but only 1 follows.
        let msg_to_user = MsgToUserTlv::new(b"cfdp\x00\x02\x01").unwrap();
        assert!(matches!(
            ProxyPutRequestMessageReader::try_from(msg_to_user),
            Err(ReservedMessageReadError::ByteConversion(_))
        ));
    }

    fn proxy_put_response() -> ProxyPutResponseMessage {
        ProxyPutResponseMessage::new(
            ConditionCode::FileChecksumFailure,
            DeliveryCode::Incomplete,
            FileStatus::Retained,
        )
    }

    #[test]
    fn test_proxy_put_response_serialization() {
        let response = proxy_put_response();
        let mut buf: [u8; 16] = [0; 16];
        let written = response.write_to_slice(&mut buf).unwrap();
        assert_eq!(written, response.len_written());
        assert_eq!(written, 2 + 4 + 1 + 1);
        assert_eq!(buf[0], TlvType::MsgToUser as u8);
        assert_eq!(buf[1], 6);
        assert_eq!(&buf[2..6], b"cfdp");
        assert_eq!(buf[6], ReservedMessageType::ProxyPutResponse as u8);
        assert_eq!(buf[7], 0b0101_0110);
    }

    #[test]
    fn test_proxy_put_response_round_trip() {
        let response = proxy_put_response();
        let mut buf: [u8; 16] = [0; 16];
        let written = response.write_to_slice(&mut buf).unwrap();
        let msg_to_user = MsgToUserTlv::from_bytes(&buf[..written]).unwrap();
        assert_eq!(
            msg_to_user.reserved_cfdp_msg_type(),
            Some(Ok(ReservedMessageType::ProxyPutResponse))
        );
        let read_back = ProxyPutResponseMessage::try_from(msg_to_user).unwrap();
        assert_eq!(read_back, response);
        assert_eq!(
            read_back.condition_code(),
            ConditionCode::FileChecksumFailure
        );
        assert_eq!(read_back.delivery_code(), DeliveryCode::Incomplete);
        assert_eq!(read_back.file_status(), FileStatus::Retained);
        assert_eq!(
            ProxyPutResponseMessage::from_bytes(&buf[..written]).unwrap(),
            response
        );
    }

    #[test]
    fn test_proxy_put_response_success() {
        let response = ProxyPutResponseMessage::new(
            ConditionCode::NoError,
            DeliveryCode::Complete,
            FileStatus::Retained,
        );
        let mut buf: [u8; 16] = [0; 16];
        let written = response.write_to_slice(&mut buf).unwrap();
        assert_eq!(buf[7], 0b0000_0010);
        let read_back = ProxyPutResponseMessage::from_bytes(&buf[..written]).unwrap();
        assert_eq!(read_back, response);
        assert_eq!(read_back.condition_code(), ConditionCode::NoError);
        assert_eq!(read_back.delivery_code(), DeliveryCode::Complete);
        assert_eq!(read_back.file_status(), FileStatus::Retained);
    }

    #[test]
    fn test_writable_tlv_impls() {
        let creator = proxy_put_request_creator();
        let mut buf: [u8; 64] = [0; 64];
        let written = creator.write_to_slice(&mut buf).unwrap();
        assert_eq!(WritableTlv::len_written(&creator), written);
        assert_eq!(WritableTlv::to_vec(&creator), buf[..written]);

        let response = proxy_put_response();
        let written = response.write_to_slice(&mut buf).unwrap();
        assert_eq!(WritableTlv::len_written(&response), written);
        assert_eq!(WritableTlv::to_vec(&response), buf[..written]);

        let transmission_mode = ProxyTransmissionModeMessage::new(TransmissionMode::Acknowledged);
        let written = transmission_mode.write_to_slice(&mut buf).unwrap();
        assert_eq!(WritableTlv::len_written(&transmission_mode), written);
        assert_eq!(WritableTlv::to_vec(&transmission_mode), buf[..written]);

        let closure_request = ProxyClosureRequestMessage::new(true);
        let written = closure_request.write_to_slice(&mut buf).unwrap();
        assert_eq!(WritableTlv::len_written(&closure_request), written);
        assert_eq!(WritableTlv::to_vec(&closure_request), buf[..written]);

        let written = ProxyPutCancelMessage.write_to_slice(&mut buf).unwrap();
        assert_eq!(WritableTlv::len_written(&ProxyPutCancelMessage), written);
        assert_eq!(WritableTlv::to_vec(&ProxyPutCancelMessage), buf[..written]);
    }

    #[test]
    fn test_proxy_put_response_buf_too_small() {
        let response = proxy_put_response();
        let mut buf: [u8; 7] = [0; 7];
        assert_eq!(
            response.write_to_slice(&mut buf),
            Err(ByteConversionError::ToSliceTooSmall {
                found: 7,
                expected: 8
            })
        );
    }

    #[test]
    fn test_proxy_put_response_missing_status() {
        let msg_to_user = MsgToUserTlv::new(b"cfdp\x07").unwrap();
        assert_eq!(
            ProxyPutResponseMessage::try_from(msg_to_user),
            Err(ReservedMessageReadError::ByteConversion(
                ByteConversionError::FromSliceTooSmall {
                    found: 0,
                    expected: 1
                }
            ))
        );
    }

    #[test]
    fn test_proxy_put_response_invalid_condition_code() {
        // 0b1001 is not a valid condition code.
        let msg_to_user = MsgToUserTlv::new(b"cfdp\x07\x90").unwrap();
        assert_eq!(
            ProxyPutResponseMessage::try_from(msg_to_user),
            Err(ReservedMessageReadError::InvalidConditionCode(0b1001))
        );
    }

    #[test]
    fn test_proxy_put_response_wrong_type() {
        let mut buf: [u8; 64] = [0; 64];
        let written = proxy_put_request_creator()
            .write_to_slice(&mut buf)
            .unwrap();
        assert_eq!(
            ProxyPutResponseMessage::from_bytes(&buf[..written]),
            Err(ReservedMessageReadError::UnexpectedMessageType {
                found: ReservedMessageType::ProxyPutRequest,
                expected: ReservedMessageType::ProxyPutResponse,
            })
        );
    }

    #[test]
    fn test_proxy_transmission_mode_serialization() {
        let msg = ProxyTransmissionModeMessage::new(TransmissionMode::Unacknowledged);
        let mut buf: [u8; 16] = [0; 16];
        let written = msg.write_to_slice(&mut buf).unwrap();
        assert_eq!(written, msg.len_written());
        assert_eq!(
            &buf[..written],
            &[
                TlvType::MsgToUser as u8,
                6,
                b'c',
                b'f',
                b'd',
                b'p',
                0x04,
                0x01
            ]
        );
    }

    #[test]
    fn test_proxy_transmission_mode_round_trip() {
        for mode in [
            TransmissionMode::Acknowledged,
            TransmissionMode::Unacknowledged,
        ] {
            let msg = ProxyTransmissionModeMessage::new(mode);
            let mut buf: [u8; 16] = [0; 16];
            let written = msg.write_to_slice(&mut buf).unwrap();
            let read_back = ProxyTransmissionModeMessage::from_bytes(&buf[..written]).unwrap();
            assert_eq!(read_back, msg);
            assert_eq!(read_back.transmission_mode(), mode);
        }
    }

    #[test]
    fn test_proxy_transmission_mode_spare_bits_ignored() {
        let msg_to_user = MsgToUserTlv::new(b"cfdp\x04\xfe").unwrap();
        assert_eq!(
            ProxyTransmissionModeMessage::try_from(msg_to_user)
                .unwrap()
                .transmission_mode(),
            TransmissionMode::Acknowledged
        );
    }

    #[test]
    fn test_proxy_transmission_mode_missing_param() {
        let msg_to_user = MsgToUserTlv::new(b"cfdp\x04").unwrap();
        assert_eq!(
            ProxyTransmissionModeMessage::try_from(msg_to_user),
            Err(ReservedMessageReadError::ByteConversion(
                ByteConversionError::FromSliceTooSmall {
                    found: 0,
                    expected: 1
                }
            ))
        );
    }

    #[test]
    fn test_proxy_transmission_mode_wrong_type() {
        let msg_to_user = MsgToUserTlv::new(b"cfdp\x0b\x01").unwrap();
        assert_eq!(
            ProxyTransmissionModeMessage::try_from(msg_to_user),
            Err(ReservedMessageReadError::UnexpectedMessageType {
                found: ReservedMessageType::ProxyClosureRequest,
                expected: ReservedMessageType::ProxyTransmissionMode,
            })
        );
    }

    #[test]
    fn test_proxy_closure_request_serialization() {
        let msg = ProxyClosureRequestMessage::new(true);
        let mut buf: [u8; 16] = [0; 16];
        let written = msg.write_to_slice(&mut buf).unwrap();
        assert_eq!(written, msg.len_written());
        assert_eq!(
            &buf[..written],
            &[
                TlvType::MsgToUser as u8,
                6,
                b'c',
                b'f',
                b'd',
                b'p',
                0x0B,
                0x01
            ]
        );
    }

    #[test]
    fn test_proxy_closure_request_round_trip() {
        for closure_requested in [false, true] {
            let msg = ProxyClosureRequestMessage::new(closure_requested);
            let mut buf: [u8; 16] = [0; 16];
            let written = msg.write_to_slice(&mut buf).unwrap();
            let read_back = ProxyClosureRequestMessage::from_bytes(&buf[..written]).unwrap();
            assert_eq!(read_back, msg);
            assert_eq!(read_back.closure_requested(), closure_requested);
        }
    }

    #[test]
    fn test_proxy_closure_request_spare_bits_ignored() {
        let msg_to_user = MsgToUserTlv::new(b"cfdp\x0b\xfe").unwrap();
        assert!(
            !ProxyClosureRequestMessage::try_from(msg_to_user)
                .unwrap()
                .closure_requested()
        );
    }

    #[test]
    fn test_proxy_closure_request_missing_param() {
        let msg_to_user = MsgToUserTlv::new(b"cfdp\x0b").unwrap();
        assert_eq!(
            ProxyClosureRequestMessage::try_from(msg_to_user),
            Err(ReservedMessageReadError::ByteConversion(
                ByteConversionError::FromSliceTooSmall {
                    found: 0,
                    expected: 1
                }
            ))
        );
    }

    #[test]
    fn test_proxy_put_cancel_serialization() {
        let msg = ProxyPutCancelMessage;
        let mut buf: [u8; 16] = [0; 16];
        let written = msg.write_to_slice(&mut buf).unwrap();
        assert_eq!(written, msg.len_written());
        assert_eq!(
            &buf[..written],
            &[TlvType::MsgToUser as u8, 5, b'c', b'f', b'd', b'p', 0x09]
        );
    }

    #[test]
    fn test_proxy_put_cancel_round_trip() {
        let mut buf: [u8; 16] = [0; 16];
        let written = ProxyPutCancelMessage.write_to_slice(&mut buf).unwrap();
        assert_eq!(
            ProxyPutCancelMessage::from_bytes(&buf[..written]),
            Ok(ProxyPutCancelMessage)
        );
    }

    #[test]
    fn test_proxy_put_cancel_wrong_type() {
        let msg_to_user = MsgToUserTlv::new(b"cfdp\x07\x00").unwrap();
        assert_eq!(
            ProxyPutCancelMessage::try_from(msg_to_user),
            Err(ReservedMessageReadError::UnexpectedMessageType {
                found: ReservedMessageType::ProxyPutResponse,
                expected: ReservedMessageType::ProxyPutCancel,
            })
        );
    }

    #[test]
    fn test_proxy_put_cancel_buf_too_small() {
        let mut buf: [u8; 6] = [0; 6];
        assert_eq!(
            ProxyPutCancelMessage.write_to_slice(&mut buf),
            Err(ByteConversionError::ToSliceTooSmall {
                found: 6,
                expected: 7
            })
        );
    }

    #[test]
    fn test_proxy_message_to_user_serialization() {
        let msg = ProxyMessageToUserMessage::new(Lv::new(&[1, 2, 3]).unwrap()).unwrap();
        let mut buf: [u8; 16] = [0; 16];
        let written = msg.write_to_slice(&mut buf).unwrap();
        assert_eq!(written, msg.len_written());
        assert_eq!(
            &buf[..written],
            &[
                TlvType::MsgToUser as u8,
                9,
                b'c',
                b'f',
                b'd',
                b'p',
                0x01,
                3,
                1,
                2,
                3
            ]
        );
    }

    #[test]
    fn test_proxy_message_to_user_round_trip() {
        let msg = ProxyMessageToUserMessage::new(Lv::new(&[1, 2, 3]).unwrap()).unwrap();
        let buf = msg.to_vec();
        let read_back = ProxyMessageToUserMessage::from_bytes(&buf).unwrap();
        assert_eq!(read_back, msg);
        assert_eq!(read_back.message_text().value(), &[1, 2, 3]);
        assert_eq!(read_back.to_msg_to_user().value(), &[1, 2, 3]);
    }

    #[test]
    fn test_proxy_message_to_user_too_large() {
        let text = [0; 251];
        assert_eq!(
            ProxyMessageToUserMessage::new(Lv::new(&text).unwrap()),
            Err(ReservedMessageCreationError::DataTooLarge(
                TlvLvDataTooLargeError(4 + 1 + 252)
            ))
        );
        assert!(ProxyMessageToUserMessage::new(Lv::new(&text[..249]).unwrap()).is_ok());
    }

    #[test]
    fn test_proxy_message_to_user_truncated() {
        // Message text LV announces 3 bytes, but only 2 follow.
        let msg_to_user = MsgToUserTlv::new(b"cfdp\x01\x03\x01\x02").unwrap();
        assert!(matches!(
            ProxyMessageToUserMessage::try_from(msg_to_user),
            Err(ReservedMessageReadError::ByteConversion(_))
        ));
    }

    fn proxy_filestore_request() -> ProxyFilestoreRequestMessage<'static, 'static> {
        ProxyFilestoreRequestMessage::new(
            FilestoreRequestTlv::new_rename_file(
                Lv::try_from("a.txt").unwrap(),
                Lv::try_from("b.txt").unwrap(),
            )
            .unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn test_proxy_filestore_request_serialization() {
        let msg = proxy_filestore_request();
        let mut buf: [u8; 32] = [0; 32];
        let written = msg.write_to_slice(&mut buf).unwrap();
        assert_eq!(written, msg.len_written());
        assert_eq!(written, 2 + 4 + 1 + 1 + 1 + 6 + 6);
        assert_eq!(buf[1] as usize, written - 2);
        assert_eq!(&buf[2..6], b"cfdp");
        assert_eq!(buf[6], ReservedMessageType::ProxyFilestoreRequest as u8);
        assert_eq!(buf[7], 13);
        assert_eq!(buf[8], (FilestoreActionCode::RenameFile as u8) << 4);
        assert_eq!(buf[9], 5);
        assert_eq!(&buf[10..15], b"a.txt");
        assert_eq!(buf[15], 5);
        assert_eq!(&buf[16..21], b"b.txt");
    }

    #[test]
    fn test_proxy_filestore_request_round_trip() {
        let msg = proxy_filestore_request();
        let buf = msg.to_vec();
        let read_back = ProxyFilestoreRequestMessage::from_bytes(&buf).unwrap();
        assert_eq!(read_back, msg);
        let request = read_back.request();
        assert_eq!(request.action_code(), FilestoreActionCode::RenameFile);
        assert_eq!(request.first_name().value_as_str(), Some(Ok("a.txt")));
        assert_eq!(
            request.second_name().unwrap().value_as_str(),
            Some(Ok("b.txt"))
        );
    }

    #[test]
    fn test_proxy_filestore_request_second_name_missing() {
        // Rename request which only contains the first name.
        let msg_to_user = MsgToUserTlv::new(b"cfdp\x02\x03\x20\x01a").unwrap();
        assert_eq!(
            ProxyFilestoreRequestMessage::try_from(msg_to_user),
            Err(ReservedMessageReadError::TlvLv(
                TlvLvError::SecondNameMissing
            ))
        );
    }

    #[test]
    fn test_proxy_filestore_request_empty() {
        let msg_to_user = MsgToUserTlv::new(b"cfdp\x02\x00").unwrap();
        assert!(matches!(
            ProxyFilestoreRequestMessage::try_from(msg_to_user),
            Err(ReservedMessageReadError::TlvLv(TlvLvError::ByteConversion(
                _
            )))
        ));
    }

    #[test]
    fn test_proxy_filestore_request_too_large() {
        let file_name = [b'a'; 125];
        let file_name = core::str::from_utf8(&file_name).unwrap();
        let request = FilestoreRequestTlv::new_rename_file(
            Lv::try_from(file_name).unwrap(),
            Lv::try_from(file_name).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            ProxyFilestoreRequestMessage::new(request),
            Err(ReservedMessageCreationError::DataTooLarge(_))
        ));
    }

    #[test]
    fn test_proxy_fault_handler_override_serialization() {
        let msg = ProxyFaultHandlerOverrideMessage::new(
            ConditionCode::FileChecksumFailure,
            FaultHandlerCode::AbandonTransaction,
        );
        let mut buf: [u8; 16] = [0; 16];
        let written = msg.write_to_slice(&mut buf).unwrap();
        assert_eq!(written, msg.len_written());
        assert_eq!(
            &buf[..written],
            &[
                TlvType::MsgToUser as u8,
                6,
                b'c',
                b'f',
                b'd',
                b'p',
                0x03,
                0b0101_0100
            ]
        );
    }

    #[test]
    fn test_proxy_fault_handler_override_round_trip() {
        let msg = ProxyFaultHandlerOverrideMessage::new(
            ConditionCode::InactivityDetected,
            FaultHandlerCode::NoticeOfSuspension,
        );
        let read_back = ProxyFaultHandlerOverrideMessage::from_bytes(&msg.to_vec()).unwrap();
        assert_eq!(read_back, msg);
        assert_eq!(
            read_back.condition_code(),
            ConditionCode::InactivityDetected
        );
        assert_eq!(
            read_back.handler_code(),
            FaultHandlerCode::NoticeOfSuspension
        );
    }

    #[test]
    fn test_proxy_fault_handler_override_invalid_codes() {
        let msg_to_user = MsgToUserTlv::new(b"cfdp\x03\x91").unwrap();
        assert_eq!(
            ProxyFaultHandlerOverrideMessage::try_from(msg_to_user),
            Err(ReservedMessageReadError::InvalidConditionCode(0b1001))
        );
        let msg_to_user = MsgToUserTlv::new(b"cfdp\x03\x10").unwrap();
        assert_eq!(
            ProxyFaultHandlerOverrideMessage::try_from(msg_to_user),
            Err(ReservedMessageReadError::InvalidFaultHandlerCode(0))
        );
    }

    #[test]
    fn test_proxy_flow_label_round_trip() {
        let msg = ProxyFlowLabelMessage::new(Lv::new(&[0xAB]).unwrap()).unwrap();
        let buf = msg.to_vec();
        assert_eq!(
            buf,
            [
                TlvType::MsgToUser as u8,
                7,
                b'c',
                b'f',
                b'd',
                b'p',
                0x05,
                1,
                0xAB
            ]
        );
        let read_back = ProxyFlowLabelMessage::from_bytes(&buf).unwrap();
        assert_eq!(read_back, msg);
        assert_eq!(read_back.flow_label().value(), &[0xAB]);
    }

    #[test]
    fn test_proxy_flow_label_too_large() {
        let label = [0; 255];
        assert!(matches!(
            ProxyFlowLabelMessage::new(Lv::new(&label).unwrap()),
            Err(ReservedMessageCreationError::DataTooLarge(_))
        ));
    }

    #[test]
    fn test_proxy_segmentation_control_serialization() {
        // The bit is inverted compared to the PDU header.
        for (segmentation_control, raw) in [
            (SegmentationControl::WithRecordBoundaryPreservation, 0),
            (SegmentationControl::NoRecordBoundaryPreservation, 1),
        ] {
            let msg = ProxySegmentationControlMessage::new(segmentation_control);
            let buf = msg.to_vec();
            assert_eq!(buf.len(), msg.len_written());
            assert_eq!(
                buf,
                [
                    TlvType::MsgToUser as u8,
                    6,
                    b'c',
                    b'f',
                    b'd',
                    b'p',
                    0x06,
                    raw
                ]
            );
            let read_back = ProxySegmentationControlMessage::from_bytes(&buf).unwrap();
            assert_eq!(read_back, msg);
            assert_eq!(read_back.segmentation_control(), segmentation_control);
        }
    }

    #[test]
    fn test_proxy_segmentation_control_spare_bits_ignored() {
        let msg_to_user = MsgToUserTlv::new(b"cfdp\x06\xfe").unwrap();
        assert_eq!(
            ProxySegmentationControlMessage::try_from(msg_to_user)
                .unwrap()
                .segmentation_control(),
            SegmentationControl::WithRecordBoundaryPreservation
        );
    }

    fn proxy_filestore_response() -> ProxyFilestoreResponseMessage<'static, 'static, 'static> {
        ProxyFilestoreResponseMessage::new(
            FilestoreResponseTlv::new(
                FilestoreActionCode::DeleteFile,
                0b0001,
                Lv::try_from("a.txt").unwrap(),
                None,
                Lv::try_from("gone").unwrap(),
            )
            .unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn test_proxy_filestore_response_serialization() {
        let msg = proxy_filestore_response();
        let mut buf: [u8; 32] = [0; 32];
        let written = msg.write_to_slice(&mut buf).unwrap();
        assert_eq!(written, msg.len_written());
        assert_eq!(written, 2 + 4 + 1 + 1 + 1 + 6 + 5);
        assert_eq!(buf[1] as usize, written - 2);
        assert_eq!(buf[6], ReservedMessageType::ProxyFilestoreResponse as u8);
        assert_eq!(buf[7], 12);
        assert_eq!(
            buf[8],
            ((FilestoreActionCode::DeleteFile as u8) << 4) | 0b0001
        );
        assert_eq!(buf[9], 5);
        assert_eq!(&buf[10..15], b"a.txt");
        assert_eq!(buf[15], 4);
        assert_eq!(&buf[16..20], b"gone");
    }

    #[test]
    fn test_proxy_filestore_response_round_trip() {
        let msg = proxy_filestore_response();
        let buf = msg.to_vec();
        let read_back = ProxyFilestoreResponseMessage::from_bytes(&buf).unwrap();
        assert_eq!(read_back, msg);
        let response = read_back.response();
        assert_eq!(response.action_code(), FilestoreActionCode::DeleteFile);
        assert_eq!(response.status_code(), 0b0001);
        assert_eq!(response.first_name().value_as_str(), Some(Ok("a.txt")));
        assert!(response.second_name().is_none());
    }

    #[test]
    fn test_proxy_filestore_response_truncated() {
        // The filestore message LV is missing.
        let msg_to_user = MsgToUserTlv::new(b"cfdp\x08\x03\x10\x01a").unwrap();
        assert!(matches!(
            ProxyFilestoreResponseMessage::try_from(msg_to_user),
            Err(ReservedMessageReadError::TlvLv(TlvLvError::ByteConversion(
                _
            )))
        ));
    }

    #[test]
    fn test_remaining_proxy_messages_writable_tlv_impls() {
        let mut buf: [u8; 64] = [0; 64];
        let messages: [&dyn WritableTlv; 6] = [
            &ProxyMessageToUserMessage::new(Lv::new(&[1, 2]).unwrap()).unwrap(),
            &proxy_filestore_request(),
            &ProxyFaultHandlerOverrideMessage::new(
                ConditionCode::NakLimitReached,
                FaultHandlerCode::IgnoreError,
            ),
            &ProxyFlowLabelMessage::new(Lv::new(&[1]).unwrap()).unwrap(),
            &ProxySegmentationControlMessage::new(
                SegmentationControl::NoRecordBoundaryPreservation,
            ),
            &proxy_filestore_response(),
        ];
        for msg in messages {
            let written = msg.write_to_slice(&mut buf).unwrap();
            assert_eq!(msg.len_written(), written);
            assert_eq!(msg.to_vec(), buf[..written]);
            let mut small_buf = [0; 6];
            assert!(matches!(
                msg.write_to_slice(&mut small_buf),
                Err(ByteConversionError::ToSliceTooSmall { .. })
            ));
        }
    }
}
