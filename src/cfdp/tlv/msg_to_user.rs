//! Abstractions for the Message to User CFDP TLV subtype.
#[cfg(feature = "alloc")]
use super::TlvOwned;
use super::{GenericTlv, Tlv, TlvLvError, TlvType, TlvTypeField, WritableTlv};
use crate::{
    ByteConversionError,
    cfdp::{
        ConditionCode, InvalidTlvTypeFieldError, TlvLvDataTooLargeError, TransmissionMode,
        lv::Lv,
        pdu::finished::{DeliveryCode, FileStatus, pack_status_byte, unpack_status_byte},
    },
    util::{UnsignedByteField, UnsignedByteFieldError},
};
use delegate::delegate;
use num_enum::{IntoPrimitive, TryFromPrimitive};

/// Message To User TLV structure.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct MsgToUserTlv<'data> {
    /// Wrapped generic TLV structure.
    pub tlv: Tlv<'data>,
}

impl<'data> MsgToUserTlv<'data> {
    /// Every reserved CFDP message value starts with this ID.
    pub const RESERVED_MESSAGE_ID: &'static [u8; 4] = b"cfdp";
    /// Length of [Self::RESERVED_MESSAGE_ID].
    pub const RESERVED_MESSAGE_ID_LEN: usize = Self::RESERVED_MESSAGE_ID.len();

    /// Create a new message to user TLV where the type field is set correctly.
    pub fn new(value: &'data [u8]) -> Result<MsgToUserTlv<'data>, TlvLvDataTooLargeError> {
        Ok(Self {
            tlv: Tlv::new(TlvType::MsgToUser, value)?,
        })
    }

    delegate! {
        to self.tlv {
            /// Value field of the TLV.
            pub fn value(&self) -> &'data [u8];

            /// Helper method to retrieve the length of the value. Simply calls the [slice::len] method of
            /// [Self::value]
            pub fn len_value(&self) -> usize;
            /// Returns the full raw length, including the length byte.
            pub fn len_full(&self) -> usize;
            /// Checks whether the value field is empty.
            pub fn is_empty(&self) -> bool;
            /// If the TLV was generated from a raw bytestream using [Self::from_bytes], the raw start
            /// of the TLV can be retrieved with this method.
            pub fn raw_data(&self) -> Option<&'data [u8]>;
        }
    }

    /// Is this a standard TLV?
    #[inline]
    pub fn is_standard_tlv(&self) -> bool {
        true
    }

    /// TLV type field.
    #[inline]
    pub fn tlv_type(&self) -> TlvType {
        TlvType::MsgToUser
    }

    /// Full TLV length of a reserved CFDP message.
    ///
    /// The payload length is the length of the message parameters following the message type.
    pub fn full_len_for_reserved_cfdp_message(payload_len: usize) -> usize {
        // 1 byte for the reserved message type.
        Tlv::MIN_LEN + Self::RESERVED_MESSAGE_ID_LEN + 1 + payload_len
    }

    /// Checks whether a reserved CFDP message with the given payload length still fits into
    /// the TLV value field.
    ///
    /// The payload length is the length of the message parameters following the message type.
    pub fn check_reserved_message_payload_len(
        payload_len: usize,
    ) -> Result<(), TlvLvDataTooLargeError> {
        // 1 byte for the reserved message type.
        let full_payload_len = Self::RESERVED_MESSAGE_ID_LEN + 1 + payload_len;
        if full_payload_len > u8::MAX as usize {
            return Err(TlvLvDataTooLargeError(full_payload_len));
        }
        Ok(())
    }

    /// Checks whether this message is a reserved CFDP message like a Proxy Operation Message.
    pub fn is_reserved_cfdp_msg(&self) -> bool {
        self.reserved_cfdp_msg_type().is_some()
    }

    /// Returns the message type if this is a reserved CFDP message like a Proxy Operation
    /// Message.
    ///
    /// Returns [None] if the value does not start with the reserved message ID, and an error
    /// if it does but the message type is missing or unknown.
    pub fn reserved_cfdp_msg_type(
        &self,
    ) -> Option<Result<ReservedMessageType, InvalidReservedMessageTypeError>> {
        let value = self.value();
        if !value.starts_with(Self::RESERVED_MESSAGE_ID) {
            return None;
        }
        Some(match value.get(Self::RESERVED_MESSAGE_ID_LEN) {
            Some(raw_type) => ReservedMessageType::try_from(*raw_type),
            None => Err(InvalidReservedMessageTypeError::Missing),
        })
    }

    /// This is a thin wrapper around [Tlv::from_bytes] with the additional type check.
    pub fn from_bytes(buf: &'data [u8]) -> Result<MsgToUserTlv<'data>, TlvLvError> {
        let msg_to_user = Self {
            tlv: Tlv::from_bytes(buf)?,
        };
        match msg_to_user.tlv.tlv_type_field() {
            TlvTypeField::Standard(tlv_type) => {
                if tlv_type != TlvType::MsgToUser {
                    return Err(InvalidTlvTypeFieldError {
                        found: tlv_type as u8,
                        expected: Some(TlvType::MsgToUser as u8),
                    }
                    .into());
                }
            }
            TlvTypeField::Custom(raw) => {
                return Err(InvalidTlvTypeFieldError {
                    found: raw,
                    expected: Some(TlvType::MsgToUser as u8),
                }
                .into());
            }
        }
        Ok(msg_to_user)
    }

    /// Convert to a generic [Tlv].
    #[inline]
    pub fn to_tlv(&self) -> Tlv<'data> {
        self.tlv
    }

    /// Convert to an [TlvOwned].
    #[cfg(feature = "alloc")]
    pub fn to_owned(&self) -> TlvOwned {
        self.tlv.to_owned()
    }

    /// Length of the written TLV.
    #[inline]
    pub fn len_written(&self) -> usize {
        self.len_full()
    }

    delegate!(
        to self.tlv {
            /// Write the TLV to a byte buffer.
            pub fn write_to_slice(&self, buf: &mut [u8]) -> Result<usize, ByteConversionError>;
            /// TLV type field.
            pub fn tlv_type_field(&self) -> TlvTypeField;
        }
    );

    /// Deprecated alias for [Self::write_to_slice].
    #[deprecated(since = "0.19.0", note = "use write_to_slice instead")]
    pub fn write_to_bytes(&self, buf: &mut [u8]) -> Result<usize, ByteConversionError> {
        self.write_to_slice(buf)
    }

    /// Write the TLV to an owned [alloc::vec::Vec].
    #[cfg(feature = "alloc")]
    pub fn to_vec(&self) -> alloc::vec::Vec<u8> {
        WritableTlv::to_vec(self)
    }
}

impl<'a> From<MsgToUserTlv<'a>> for Tlv<'a> {
    fn from(value: MsgToUserTlv<'a>) -> Tlv<'a> {
        value.to_tlv()
    }
}

impl WritableTlv for MsgToUserTlv<'_> {
    #[inline]
    fn len_written(&self) -> usize {
        self.len_written()
    }

    fn write_to_slice(&self, buf: &mut [u8]) -> Result<usize, ByteConversionError> {
        self.tlv.write_to_slice(buf)
    }
}

impl GenericTlv for MsgToUserTlv<'_> {
    #[inline]
    fn tlv_type_field(&self) -> TlvTypeField {
        self.tlv_type_field()
    }
}

/// Message types of the reserved CFDP messages.
#[derive(Debug, PartialEq, Eq, Clone, Copy, TryFromPrimitive, IntoPrimitive)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[num_enum(error_type(
    name = InvalidReservedMessageTypeError,
    constructor = InvalidReservedMessageTypeError::Unknown
))]
#[repr(u8)]
pub enum ReservedMessageType {
    /// Proxy put request.
    ProxyPutRequest = 0x00,
    /// Proxy message to user.
    ProxyMessageToUser = 0x01,
    /// Proxy filestore request.
    ProxyFilestoreRequest = 0x02,
    /// Proxy fault handler override.
    ProxyFaultHandlerOverride = 0x03,
    /// Proxy transmission mode.
    ProxyTransmissionMode = 0x04,
    /// Proxy flow label.
    ProxyFlowLabel = 0x05,
    /// Proxy segmentation control.
    ProxySegmentationControl = 0x06,
    /// Proxy put response.
    ProxyPutResponse = 0x07,
    /// Proxy filestore response.
    ProxyFilestoreResponse = 0x08,
    /// Proxy put cancel.
    ProxyPutCancel = 0x09,
    /// Originating transaction ID.
    OriginatingTransactionId = 0x0A,
    /// Proxy closure request.
    ProxyClosureRequest = 0x0B,
    /// Directory listing request.
    DirectoryListingRequest = 0x10,
    /// Directory listing response.
    DirectoryListingResponse = 0x11,
    /// Remote status report request.
    RemoteStatusReportRequest = 0x20,
    /// Remote status report response.
    RemoteStatusReportResponse = 0x21,
    /// Remote suspend request.
    RemoteSuspendRequest = 0x30,
    /// Remote suspend response.
    RemoteSuspendResponse = 0x31,
    /// Remote resume request.
    RemoteResumeRequest = 0x38,
    /// Remote resume response.
    RemoteResumeResponse = 0x39,
}

impl ReservedMessageType {
    /// Is this a proxy operation message type?
    pub fn is_proxy(&self) -> bool {
        // The originating transaction ID is not a proxy message, but sits in the proxy range.
        matches!(*self as u8, 0x00..=0x09 | 0x0B)
    }
}

/// Invalid message type field of a reserved CFDP message.
#[derive(Debug, Copy, Clone, PartialEq, Eq, thiserror::Error)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum InvalidReservedMessageTypeError {
    /// The value only contains the reserved message ID.
    #[error("reserved message type is missing")]
    Missing,
    /// Unknown raw message type.
    #[error("unknown reserved message type {0}")]
    Unknown(u8),
}

/// Errors when creating a reserved CFDP message.
#[derive(Debug, Copy, Clone, PartialEq, Eq, thiserror::Error)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ReservedMessageCreationError {
    /// Message does not fit into the TLV value field.
    #[error("{0}")]
    DataTooLarge(#[from] TlvLvDataTooLargeError),
    /// Invalid entity ID.
    #[error("invalid entity ID: {0}")]
    InvalidEntityId(#[from] UnsignedByteFieldError),
    /// Invalid transaction sequence number.
    #[error("invalid transaction sequence number: {0}")]
    InvalidTransactionSeqNum(UnsignedByteFieldError),
}

/// Entity IDs and transaction sequence numbers must be 1, 2, 4 or 8 bytes wide.
fn check_byte_field_width(width: usize) -> Result<(), UnsignedByteFieldError> {
    if !matches!(width, 1 | 2 | 4 | 8) {
        return Err(UnsignedByteFieldError::InvalidWidth {
            found: width,
            expected: None,
        });
    }
    Ok(())
}

/// Errors when reading a specific reserved CFDP message.
#[derive(Debug, Copy, Clone, PartialEq, Eq, thiserror::Error)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ReservedMessageReadError {
    /// Message to user TLV is not a reserved CFDP message.
    #[error("not a reserved CFDP message")]
    NotReservedMessage,
    /// Invalid message type field.
    #[error("{0}")]
    InvalidMessageType(#[from] InvalidReservedMessageTypeError),
    /// Valid message type, but not the one expected by the reader.
    #[error("unexpected reserved message type {found:?}, expected {expected:?}")]
    UnexpectedMessageType {
        /// Found message type.
        found: ReservedMessageType,
        /// Expected message type.
        expected: ReservedMessageType,
    },
    /// Generic TLV or LV error.
    #[error("{0}")]
    TlvLv(#[from] TlvLvError),
    /// Byte conversion error.
    #[error("byte conversion error: {0}")]
    ByteConversion(#[from] ByteConversionError),
    /// Invalid entity ID.
    #[error("invalid entity ID: {0}")]
    InvalidEntityId(#[from] UnsignedByteFieldError),
    /// Invalid transaction sequence number.
    #[error("invalid transaction sequence number: {0}")]
    InvalidTransactionSeqNum(UnsignedByteFieldError),
    /// Invalid condition code.
    #[error("invalid condition code {0}")]
    InvalidConditionCode(u8),
}

impl<'data> MsgToUserTlv<'data> {
    /// Checks the reserved message type and returns the message parameters following it.
    fn reserved_msg_params(
        &self,
        expected: ReservedMessageType,
    ) -> Result<&'data [u8], ReservedMessageReadError> {
        let msg_type = self
            .reserved_cfdp_msg_type()
            .ok_or(ReservedMessageReadError::NotReservedMessage)??;
        if msg_type != expected {
            return Err(ReservedMessageReadError::UnexpectedMessageType {
                found: msg_type,
                expected,
            });
        }
        // Go through the inner LV so the parameters borrow from the original buffer.
        Ok(&self.tlv.lv.value()[Self::RESERVED_MESSAGE_ID_LEN + 1..])
    }
}

/// Writes the TLV header, the reserved message ID and the message type.
///
/// The payload length must have been checked with
/// [MsgToUserTlv::check_reserved_message_payload_len]. Returns the number of bytes written.
fn write_reserved_msg_header(
    buf: &mut [u8],
    msg_type: ReservedMessageType,
    payload_len: usize,
) -> Result<usize, ByteConversionError> {
    let full_len = MsgToUserTlv::full_len_for_reserved_cfdp_message(payload_len);
    if full_len > buf.len() {
        return Err(ByteConversionError::ToSliceTooSmall {
            found: buf.len(),
            expected: full_len,
        });
    }
    buf[0] = TlvType::MsgToUser as u8;
    buf[1] = (full_len - Tlv::MIN_LEN) as u8;
    buf[2..6].copy_from_slice(MsgToUserTlv::RESERVED_MESSAGE_ID);
    buf[6] = msg_type as u8;
    Ok(Tlv::MIN_LEN + MsgToUserTlv::RESERVED_MESSAGE_ID_LEN + 1)
}

/// Reads the first parameter byte of a reserved message which has a single byte parameter.
fn read_single_byte_param(params: &[u8]) -> Result<u8, ByteConversionError> {
    params
        .first()
        .copied()
        .ok_or(ByteConversionError::FromSliceTooSmall {
            found: 0,
            expected: 1,
        })
}

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

/// Originating transaction ID message.
///
/// Identifies the transaction which originated a reserved message exchange, for example the
/// proxy put request a proxy put response belongs to.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct OriginatingTransactionIdMessage {
    source_entity_id: UnsignedByteField,
    transaction_seq_num: UnsignedByteField,
}

impl OriginatingTransactionIdMessage {
    /// Constructor for the originating transaction ID message.
    pub fn new(
        source_entity_id: UnsignedByteField,
        transaction_seq_num: UnsignedByteField,
    ) -> Result<Self, ReservedMessageCreationError> {
        check_byte_field_width(source_entity_id.size())?;
        check_byte_field_width(transaction_seq_num.size())
            .map_err(ReservedMessageCreationError::InvalidTransactionSeqNum)?;
        Ok(Self {
            source_entity_id,
            transaction_seq_num,
        })
    }

    /// Read an originating transaction ID message from a raw message to user TLV.
    pub fn from_bytes(buf: &[u8]) -> Result<Self, ReservedMessageReadError> {
        Self::try_from(MsgToUserTlv::from_bytes(buf)?)
    }

    /// Source entity ID of the originating transaction.
    #[inline]
    pub fn source_entity_id(&self) -> UnsignedByteField {
        self.source_entity_id
    }

    /// Transaction sequence number of the originating transaction.
    #[inline]
    pub fn transaction_seq_num(&self) -> UnsignedByteField {
        self.transaction_seq_num
    }

    /// Full written length.
    #[inline]
    pub fn len_written(&self) -> usize {
        MsgToUserTlv::full_len_for_reserved_cfdp_message(self.payload_len())
    }

    #[inline]
    fn payload_len(&self) -> usize {
        // One byte for both length fields.
        1 + self.source_entity_id.size() + self.transaction_seq_num.size()
    }

    /// Write the originating transaction ID message into a raw byte buffer.
    ///
    /// Returns the number of bytes written into the provided buffer.
    pub fn write_to_slice(&self, buf: &mut [u8]) -> Result<usize, ByteConversionError> {
        let mut current_index = write_reserved_msg_header(
            buf,
            ReservedMessageType::OriginatingTransactionId,
            self.payload_len(),
        )?;
        // Same encoding as the length fields in the PDU header: the lengths minus one, each in
        // a 3 bit field preceded by a spare bit.
        buf[current_index] = (((self.source_entity_id.size() - 1) as u8) << 4)
            | ((self.transaction_seq_num.size() - 1) as u8);
        current_index += 1;
        current_index += self
            .source_entity_id
            .write_to_slice_be(&mut buf[current_index..])?;
        current_index += self
            .transaction_seq_num
            .write_to_slice_be(&mut buf[current_index..])?;
        Ok(current_index)
    }

    /// Write the message to an owned [alloc::vec::Vec].
    #[cfg(feature = "alloc")]
    pub fn to_vec(&self) -> alloc::vec::Vec<u8> {
        WritableTlv::to_vec(self)
    }
}

impl TryFrom<MsgToUserTlv<'_>> for OriginatingTransactionIdMessage {
    type Error = ReservedMessageReadError;

    fn try_from(msg_to_user: MsgToUserTlv<'_>) -> Result<Self, Self::Error> {
        let params =
            msg_to_user.reserved_msg_params(ReservedMessageType::OriginatingTransactionId)?;
        let lengths = read_single_byte_param(params)?;
        let entity_id_len = (((lengths >> 4) & 0b111) + 1) as usize;
        let seq_num_len = ((lengths & 0b111) + 1) as usize;
        check_byte_field_width(entity_id_len)?;
        check_byte_field_width(seq_num_len)
            .map_err(ReservedMessageReadError::InvalidTransactionSeqNum)?;
        let expected_len = 1 + entity_id_len + seq_num_len;
        if params.len() < expected_len {
            return Err(ByteConversionError::FromSliceTooSmall {
                found: params.len(),
                expected: expected_len,
            }
            .into());
        }
        let source_entity_id =
            UnsignedByteField::new_from_be_bytes(entity_id_len, &params[1..1 + entity_id_len])?;
        let transaction_seq_num =
            UnsignedByteField::new_from_be_bytes(seq_num_len, &params[1 + entity_id_len..])
                .map_err(ReservedMessageReadError::InvalidTransactionSeqNum)?;
        Ok(Self {
            source_entity_id,
            transaction_seq_num,
        })
    }
}

impl WritableTlv for OriginatingTransactionIdMessage {
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

    #[test]
    fn test_basic() {
        let custom_value: [u8; 4] = [1, 2, 3, 4];
        let msg_to_user = MsgToUserTlv::new(&custom_value);
        assert!(msg_to_user.is_ok());
        let msg_to_user = msg_to_user.unwrap();
        assert!(msg_to_user.is_standard_tlv());
        assert_eq!(msg_to_user.tlv_type(), TlvType::MsgToUser);
        assert_eq!(
            msg_to_user.tlv_type_field(),
            TlvTypeField::Standard(TlvType::MsgToUser)
        );
        assert_eq!(msg_to_user.value(), custom_value);
        assert_eq!(msg_to_user.value().len(), 4);
        assert_eq!(msg_to_user.len_value(), 4);
        assert_eq!(msg_to_user.len_full(), 6);
        assert!(!msg_to_user.is_empty());
        assert!(msg_to_user.raw_data().is_none());
        assert!(!msg_to_user.is_reserved_cfdp_msg());
        assert!(msg_to_user.reserved_cfdp_msg_type().is_none());
    }

    #[test]
    fn test_reserved_msg_serialization() {
        let custom_value: [u8; 4] = [1, 2, 3, 4];
        let msg_to_user = MsgToUserTlv::new(&custom_value).unwrap();
        let mut buf: [u8; 6] = [0; 6];
        msg_to_user.write_to_slice(&mut buf).unwrap();
        assert_eq!(
            buf,
            [
                TlvType::MsgToUser as u8,
                custom_value.len() as u8,
                1,
                2,
                3,
                4
            ]
        );
    }

    #[test]
    fn test_msg_to_user_type_reduction() {
        let custom_value: [u8; 4] = [1, 2, 3, 4];
        let msg_to_user = MsgToUserTlv::new(&custom_value).unwrap();
        let tlv = msg_to_user.to_tlv();
        assert_eq!(
            tlv.tlv_type_field(),
            TlvTypeField::Standard(TlvType::MsgToUser)
        );

        assert_eq!(tlv.value(), custom_value);
    }

    #[test]
    fn test_msg_to_user_to_tlv() {
        let custom_value: [u8; 4] = [1, 2, 3, 4];
        let msg_to_user = MsgToUserTlv::new(&custom_value).unwrap();
        let tlv: Tlv = msg_to_user.into();
        assert_eq!(msg_to_user.to_tlv(), tlv);
    }

    #[test]
    fn test_msg_to_user_owner_converter() {
        let custom_value: [u8; 4] = [1, 2, 3, 4];
        let msg_to_user = MsgToUserTlv::new(&custom_value).unwrap();
        let tlv = msg_to_user.to_owned();
        assert_eq!(
            tlv.tlv_type_field(),
            TlvTypeField::Standard(TlvType::MsgToUser)
        );

        assert_eq!(tlv.value(), custom_value);
    }

    #[test]
    fn test_reserved_msg_deserialization() {
        let custom_value: [u8; 3] = [1, 2, 3];
        let msg_to_user = MsgToUserTlv::new(&custom_value).unwrap();
        let msg_to_user_vec = msg_to_user.to_vec();
        let msg_to_user_from_bytes = MsgToUserTlv::from_bytes(&msg_to_user_vec).unwrap();
        assert!(msg_to_user.reserved_cfdp_msg_type().is_none());
        assert_eq!(msg_to_user_from_bytes, msg_to_user);
        assert_eq!(msg_to_user_from_bytes.value(), msg_to_user.value());
        assert_eq!(msg_to_user_from_bytes.tlv_type(), msg_to_user.tlv_type());
    }
    #[test]
    fn test_reserved_msg_deserialization_invalid_type() {
        let trash: [u8; 5] = [TlvType::FlowLabel as u8, 3, 1, 2, 3];
        let error = MsgToUserTlv::from_bytes(&trash).unwrap_err();
        if let TlvLvError::InvalidTlvTypeField(inner) = error {
            assert_eq!(inner.found, TlvType::FlowLabel as u8);
            assert_eq!(inner.expected, Some(TlvType::MsgToUser as u8));
        } else {
            panic!("Wrong error type returned: {:?}", error);
        }
    }

    #[test]
    fn test_reserved_msg_type_missing() {
        let msg_to_user = MsgToUserTlv::new(b"cfdp").unwrap();
        assert!(msg_to_user.is_reserved_cfdp_msg());
        assert_eq!(
            msg_to_user.reserved_cfdp_msg_type(),
            Some(Err(InvalidReservedMessageTypeError::Missing))
        );
    }

    #[test]
    fn test_reserved_msg_type_unknown() {
        let msg_to_user = MsgToUserTlv::new(b"cfdp\xff").unwrap();
        assert_eq!(
            msg_to_user.reserved_cfdp_msg_type(),
            Some(Err(InvalidReservedMessageTypeError::Unknown(0xff)))
        );
    }

    #[test]
    fn test_reserved_msg_type() {
        let msg_to_user = MsgToUserTlv::new(b"cfdp\x38").unwrap();
        assert_eq!(
            msg_to_user.reserved_cfdp_msg_type(),
            Some(Ok(ReservedMessageType::RemoteResumeRequest))
        );
    }

    #[test]
    fn test_reserved_msg_type_conversion() {
        let mut valid_types = 0;
        for raw in 0..=u8::MAX {
            if let Ok(msg_type) = ReservedMessageType::try_from(raw) {
                assert_eq!(u8::from(msg_type), raw);
                valid_types += 1;
            }
        }
        assert_eq!(valid_types, 20);
        assert_eq!(
            ReservedMessageType::try_from(0x00),
            Ok(ReservedMessageType::ProxyPutRequest)
        );
        assert_eq!(
            ReservedMessageType::try_from(0x0A),
            Ok(ReservedMessageType::OriginatingTransactionId)
        );
        assert_eq!(
            ReservedMessageType::try_from(0x0C),
            Err(InvalidReservedMessageTypeError::Unknown(0x0C))
        );
    }

    #[test]
    fn test_reserved_msg_type_is_proxy() {
        let proxy_types = (0..=u8::MAX)
            .filter_map(|raw| ReservedMessageType::try_from(raw).ok())
            .filter(|msg_type| msg_type.is_proxy())
            .count();
        assert_eq!(proxy_types, 11);
        assert!(ReservedMessageType::ProxyPutRequest.is_proxy());
        assert!(ReservedMessageType::ProxyPutCancel.is_proxy());
        assert!(ReservedMessageType::ProxyClosureRequest.is_proxy());
        assert!(!ReservedMessageType::OriginatingTransactionId.is_proxy());
        assert!(!ReservedMessageType::DirectoryListingRequest.is_proxy());
    }

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

        let transaction_id = originating_transaction_id();
        let written = transaction_id.write_to_slice(&mut buf).unwrap();
        assert_eq!(WritableTlv::len_written(&transaction_id), written);
        assert_eq!(WritableTlv::to_vec(&transaction_id), buf[..written]);
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
    fn test_data_outlives_msg_to_user() {
        let buf: [u8; 6] = [TlvType::MsgToUser as u8, 4, 1, 2, 3, 4];
        let (value, raw_data) = {
            let msg_to_user = MsgToUserTlv::from_bytes(&buf).unwrap();
            (msg_to_user.value(), msg_to_user.raw_data())
        };
        assert_eq!(value, &[1, 2, 3, 4]);
        assert_eq!(raw_data, Some(&buf[..]));
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

    fn originating_transaction_id() -> OriginatingTransactionIdMessage {
        OriginatingTransactionIdMessage::new(
            UnsignedByteField::new(2, 0x0102),
            UnsignedByteField::new(4, 0x0A0B_0C0D),
        )
        .unwrap()
    }

    #[test]
    fn test_originating_transaction_id_serialization() {
        let msg = originating_transaction_id();
        let mut buf: [u8; 32] = [0; 32];
        let written = msg.write_to_slice(&mut buf).unwrap();
        assert_eq!(written, msg.len_written());
        assert_eq!(
            &buf[..written],
            &[
                TlvType::MsgToUser as u8,
                12,
                b'c',
                b'f',
                b'd',
                b'p',
                0x0A,
                0b0001_0011,
                0x01,
                0x02,
                0x0A,
                0x0B,
                0x0C,
                0x0D
            ]
        );
    }

    #[test]
    fn test_originating_transaction_id_round_trip() {
        for (entity_id_width, seq_num_width) in [(1, 1), (1, 8), (2, 4), (4, 2), (8, 1), (8, 8)] {
            let msg = OriginatingTransactionIdMessage::new(
                UnsignedByteField::new(entity_id_width, 5),
                UnsignedByteField::new(seq_num_width, 42),
            )
            .unwrap();
            let mut buf: [u8; 32] = [0; 32];
            let written = msg.write_to_slice(&mut buf).unwrap();
            let read_back = OriginatingTransactionIdMessage::from_bytes(&buf[..written]).unwrap();
            assert_eq!(read_back, msg);
            assert_eq!(
                read_back.source_entity_id(),
                UnsignedByteField::new(entity_id_width, 5)
            );
            assert_eq!(
                read_back.transaction_seq_num(),
                UnsignedByteField::new(seq_num_width, 42)
            );
        }
    }

    #[test]
    fn test_originating_transaction_id_invalid_widths() {
        assert_eq!(
            OriginatingTransactionIdMessage::new(
                UnsignedByteField::new(3, 0),
                UnsignedByteField::new(2, 0)
            ),
            Err(ReservedMessageCreationError::InvalidEntityId(
                UnsignedByteFieldError::InvalidWidth {
                    found: 3,
                    expected: None
                }
            ))
        );
        assert_eq!(
            OriginatingTransactionIdMessage::new(
                UnsignedByteField::new(2, 0),
                UnsignedByteField::new(0, 0)
            ),
            Err(ReservedMessageCreationError::InvalidTransactionSeqNum(
                UnsignedByteFieldError::InvalidWidth {
                    found: 0,
                    expected: None
                }
            ))
        );
    }

    #[test]
    fn test_originating_transaction_id_reader_invalid_widths() {
        // Entity ID length field 2 encodes a width of 3.
        let msg_to_user = MsgToUserTlv::new(b"cfdp\x0a\x20\x01\x02\x03\x04").unwrap();
        assert_eq!(
            OriginatingTransactionIdMessage::try_from(msg_to_user),
            Err(ReservedMessageReadError::InvalidEntityId(
                UnsignedByteFieldError::InvalidWidth {
                    found: 3,
                    expected: None
                }
            ))
        );
        // Sequence number length field 4 encodes a width of 5.
        let msg_to_user = MsgToUserTlv::new(b"cfdp\x0a\x04\x01\x01\x02\x03\x04\x05").unwrap();
        assert_eq!(
            OriginatingTransactionIdMessage::try_from(msg_to_user),
            Err(ReservedMessageReadError::InvalidTransactionSeqNum(
                UnsignedByteFieldError::InvalidWidth {
                    found: 5,
                    expected: None
                }
            ))
        );
    }

    #[test]
    fn test_originating_transaction_id_spare_bits_ignored() {
        let msg_to_user = MsgToUserTlv::new(b"cfdp\x0a\x88\x01\x02").unwrap();
        let msg = OriginatingTransactionIdMessage::try_from(msg_to_user).unwrap();
        assert_eq!(msg.source_entity_id(), UnsignedByteField::new(1, 1));
        assert_eq!(msg.transaction_seq_num(), UnsignedByteField::new(1, 2));
    }

    #[test]
    fn test_originating_transaction_id_truncated() {
        // Announces a 2 byte entity ID and a 4 byte sequence number, but only 3 bytes follow.
        let msg_to_user = MsgToUserTlv::new(b"cfdp\x0a\x13\x01\x02\x03").unwrap();
        assert_eq!(
            OriginatingTransactionIdMessage::try_from(msg_to_user),
            Err(ReservedMessageReadError::ByteConversion(
                ByteConversionError::FromSliceTooSmall {
                    found: 4,
                    expected: 7
                }
            ))
        );
    }

    #[test]
    fn test_originating_transaction_id_missing_param() {
        let msg_to_user = MsgToUserTlv::new(b"cfdp\x0a").unwrap();
        assert_eq!(
            OriginatingTransactionIdMessage::try_from(msg_to_user),
            Err(ReservedMessageReadError::ByteConversion(
                ByteConversionError::FromSliceTooSmall {
                    found: 0,
                    expected: 1
                }
            ))
        );
    }

    #[test]
    fn test_originating_transaction_id_wrong_type() {
        let mut buf: [u8; 16] = [0; 16];
        let written = ProxyPutCancelMessage.write_to_slice(&mut buf).unwrap();
        assert_eq!(
            OriginatingTransactionIdMessage::from_bytes(&buf[..written]),
            Err(ReservedMessageReadError::UnexpectedMessageType {
                found: ReservedMessageType::ProxyPutCancel,
                expected: ReservedMessageType::OriginatingTransactionId,
            })
        );
>>>>>>> 2392703 (more proxy message support)
    }
}
