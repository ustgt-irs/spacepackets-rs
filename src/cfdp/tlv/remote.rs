//! Remote status report, suspend and resume messages as specified in CCSDS 727.0-B-5
//! chapters 6.4 to 6.6.
use super::WritableTlv;
use super::msg_to_user::{
    MsgToUserTlv, ReservedMessageCreationError, ReservedMessageReadError, ReservedMessageType,
    TransactionIdField, read_single_byte_param, write_reserved_msg_header,
};
use crate::{
    ByteConversionError,
    cfdp::{TransactionStatus, lv::Lv},
    util::UnsignedByteField,
};

/// Remote status report request message.
///
/// Requests a status report for a transaction. The responding user puts the report into the
/// report file at the filestore of the requesting user.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct RemoteStatusReportRequestMessage<'data> {
    transaction_id: TransactionIdField,
    report_file_name: Lv<'data>,
}

impl<'data> RemoteStatusReportRequestMessage<'data> {
    /// Constructor for the remote status report request message.
    pub fn new(
        source_entity_id: UnsignedByteField,
        transaction_seq_num: UnsignedByteField,
        report_file_name: Lv<'data>,
    ) -> Result<Self, ReservedMessageCreationError> {
        let transaction_id = TransactionIdField::new(source_entity_id, transaction_seq_num)?;
        MsgToUserTlv::check_reserved_message_payload_len(
            transaction_id.len() + report_file_name.len_full(),
        )?;
        Ok(Self {
            transaction_id,
            report_file_name,
        })
    }

    /// Read a remote status report request message from a raw message to user TLV.
    pub fn from_bytes(buf: &'data [u8]) -> Result<Self, ReservedMessageReadError> {
        Self::try_from(MsgToUserTlv::from_bytes(buf)?)
    }

    /// Source entity ID of the transaction.
    #[inline]
    pub fn source_entity_id(&self) -> UnsignedByteField {
        self.transaction_id.source_entity_id
    }

    /// Transaction sequence number of the transaction.
    #[inline]
    pub fn transaction_seq_num(&self) -> UnsignedByteField {
        self.transaction_id.transaction_seq_num
    }

    /// Report file name at the filestore of the requesting user.
    #[inline]
    pub fn report_file_name(&self) -> Lv<'data> {
        self.report_file_name
    }

    #[inline]
    fn payload_len(&self) -> usize {
        self.transaction_id.len() + self.report_file_name.len_full()
    }

    /// Full written length.
    #[inline]
    pub fn len_written(&self) -> usize {
        MsgToUserTlv::full_len_for_reserved_cfdp_message(self.payload_len())
    }

    /// Write the remote status report request message into a raw byte buffer.
    ///
    /// Returns the number of bytes written into the provided buffer.
    pub fn write_to_slice(&self, buf: &mut [u8]) -> Result<usize, ByteConversionError> {
        let mut current_index = write_reserved_msg_header(
            buf,
            ReservedMessageType::RemoteStatusReportRequest,
            self.payload_len(),
        )?;
        current_index += self
            .transaction_id
            .write_to_slice(&mut buf[current_index..])?;
        current_index += self
            .report_file_name
            .write_to_slice(&mut buf[current_index..])?;
        Ok(current_index)
    }

    /// Write the message to an owned [alloc::vec::Vec].
    #[cfg(feature = "alloc")]
    pub fn to_vec(&self) -> alloc::vec::Vec<u8> {
        WritableTlv::to_vec(self)
    }
}

impl<'data> TryFrom<MsgToUserTlv<'data>> for RemoteStatusReportRequestMessage<'data> {
    type Error = ReservedMessageReadError;

    fn try_from(msg_to_user: MsgToUserTlv<'data>) -> Result<Self, Self::Error> {
        let params =
            msg_to_user.reserved_msg_params(ReservedMessageType::RemoteStatusReportRequest)?;
        let transaction_id = TransactionIdField::from_bytes(params)?;
        Ok(Self {
            transaction_id,
            report_file_name: Lv::from_bytes(&params[transaction_id.len()..])?,
        })
    }
}

impl WritableTlv for RemoteStatusReportRequestMessage<'_> {
    fn write_to_slice(&self, buf: &mut [u8]) -> Result<usize, ByteConversionError> {
        self.write_to_slice(buf)
    }

    #[inline]
    fn len_written(&self) -> usize {
        self.len_written()
    }
}

/// Remote status report response message.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct RemoteStatusReportResponseMessage {
    transaction_id: TransactionIdField,
    transaction_status: TransactionStatus,
    successful: bool,
}

impl RemoteStatusReportResponseMessage {
    /// Constructor for the remote status report response message.
    ///
    /// The successful flag is the report response code. It is false if the responding user
    /// could not provide a status report file.
    pub fn new(
        source_entity_id: UnsignedByteField,
        transaction_seq_num: UnsignedByteField,
        transaction_status: TransactionStatus,
        successful: bool,
    ) -> Result<Self, ReservedMessageCreationError> {
        Ok(Self {
            transaction_id: TransactionIdField::new(source_entity_id, transaction_seq_num)?,
            transaction_status,
            successful,
        })
    }

    /// Read a remote status report response message from a raw message to user TLV.
    pub fn from_bytes(buf: &[u8]) -> Result<Self, ReservedMessageReadError> {
        Self::try_from(MsgToUserTlv::from_bytes(buf)?)
    }

    /// Source entity ID of the transaction.
    #[inline]
    pub fn source_entity_id(&self) -> UnsignedByteField {
        self.transaction_id.source_entity_id
    }

    /// Transaction sequence number of the transaction.
    #[inline]
    pub fn transaction_seq_num(&self) -> UnsignedByteField {
        self.transaction_id.transaction_seq_num
    }

    /// Transaction status.
    #[inline]
    pub fn transaction_status(&self) -> TransactionStatus {
        self.transaction_status
    }

    /// Was the status report request successful?
    #[inline]
    pub fn successful(&self) -> bool {
        self.successful
    }

    #[inline]
    fn payload_len(&self) -> usize {
        1 + self.transaction_id.len()
    }

    /// Full written length.
    #[inline]
    pub fn len_written(&self) -> usize {
        MsgToUserTlv::full_len_for_reserved_cfdp_message(self.payload_len())
    }

    /// Write the remote status report response message into a raw byte buffer.
    ///
    /// Returns the number of bytes written into the provided buffer.
    pub fn write_to_slice(&self, buf: &mut [u8]) -> Result<usize, ByteConversionError> {
        let mut current_index = write_reserved_msg_header(
            buf,
            ReservedMessageType::RemoteStatusReportResponse,
            self.payload_len(),
        )?;
        buf[current_index] = ((self.transaction_status as u8) << 6) | self.successful as u8;
        current_index += 1;
        Ok(current_index
            + self
                .transaction_id
                .write_to_slice(&mut buf[current_index..])?)
    }

    /// Write the message to an owned [alloc::vec::Vec].
    #[cfg(feature = "alloc")]
    pub fn to_vec(&self) -> alloc::vec::Vec<u8> {
        WritableTlv::to_vec(self)
    }
}

impl TryFrom<MsgToUserTlv<'_>> for RemoteStatusReportResponseMessage {
    type Error = ReservedMessageReadError;

    fn try_from(msg_to_user: MsgToUserTlv<'_>) -> Result<Self, Self::Error> {
        let params =
            msg_to_user.reserved_msg_params(ReservedMessageType::RemoteStatusReportResponse)?;
        let status = read_single_byte_param(params)?;
        Ok(Self {
            transaction_id: TransactionIdField::from_bytes(&params[1..])?,
            // Two bits cover the full value range, so the conversion can not fail.
            transaction_status: TransactionStatus::try_from((status >> 6) & 0b11).unwrap(),
            successful: status & 0b1 == 1,
        })
    }
}

impl WritableTlv for RemoteStatusReportResponseMessage {
    fn write_to_slice(&self, buf: &mut [u8]) -> Result<usize, ByteConversionError> {
        self.write_to_slice(buf)
    }

    #[inline]
    fn len_written(&self) -> usize {
        self.len_written()
    }
}

/// First byte of the remote suspend and resume responses: the suspension indicator followed by
/// the transaction status and 5 spare bits.
fn write_suspension_status_byte(suspended: bool, transaction_status: TransactionStatus) -> u8 {
    ((suspended as u8) << 7) | ((transaction_status as u8) << 5)
}

fn read_suspension_status_byte(byte: u8) -> (bool, TransactionStatus) {
    // Two bits cover the full value range, so the conversion can not fail.
    (
        (byte >> 7) & 0b1 == 1,
        TransactionStatus::try_from((byte >> 5) & 0b11).unwrap(),
    )
}

/// Remote suspend request message.
///
/// Requests the suspension of a transaction. It must be sent with acknowledged transmission mode.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct RemoteSuspendRequestMessage {
    transaction_id: TransactionIdField,
}

impl RemoteSuspendRequestMessage {
    /// Constructor for the remote suspend request message.
    pub fn new(
        source_entity_id: UnsignedByteField,
        transaction_seq_num: UnsignedByteField,
    ) -> Result<Self, ReservedMessageCreationError> {
        Ok(Self {
            transaction_id: TransactionIdField::new(source_entity_id, transaction_seq_num)?,
        })
    }

    /// Read a remote suspend request message from a raw message to user TLV.
    pub fn from_bytes(buf: &[u8]) -> Result<Self, ReservedMessageReadError> {
        Self::try_from(MsgToUserTlv::from_bytes(buf)?)
    }

    /// Source entity ID of the transaction.
    #[inline]
    pub fn source_entity_id(&self) -> UnsignedByteField {
        self.transaction_id.source_entity_id
    }

    /// Transaction sequence number of the transaction.
    #[inline]
    pub fn transaction_seq_num(&self) -> UnsignedByteField {
        self.transaction_id.transaction_seq_num
    }

    /// Full written length.
    #[inline]
    pub fn len_written(&self) -> usize {
        MsgToUserTlv::full_len_for_reserved_cfdp_message(self.transaction_id.len())
    }

    /// Write the remote suspend request message into a raw byte buffer.
    ///
    /// Returns the number of bytes written into the provided buffer.
    pub fn write_to_slice(&self, buf: &mut [u8]) -> Result<usize, ByteConversionError> {
        let current_index = write_reserved_msg_header(
            buf,
            ReservedMessageType::RemoteSuspendRequest,
            self.transaction_id.len(),
        )?;
        Ok(current_index
            + self
                .transaction_id
                .write_to_slice(&mut buf[current_index..])?)
    }

    /// Write the message to an owned [alloc::vec::Vec].
    #[cfg(feature = "alloc")]
    pub fn to_vec(&self) -> alloc::vec::Vec<u8> {
        WritableTlv::to_vec(self)
    }
}

impl TryFrom<MsgToUserTlv<'_>> for RemoteSuspendRequestMessage {
    type Error = ReservedMessageReadError;

    fn try_from(msg_to_user: MsgToUserTlv<'_>) -> Result<Self, Self::Error> {
        let params = msg_to_user.reserved_msg_params(ReservedMessageType::RemoteSuspendRequest)?;
        Ok(Self {
            transaction_id: TransactionIdField::from_bytes(params)?,
        })
    }
}

impl WritableTlv for RemoteSuspendRequestMessage {
    fn write_to_slice(&self, buf: &mut [u8]) -> Result<usize, ByteConversionError> {
        self.write_to_slice(buf)
    }

    #[inline]
    fn len_written(&self) -> usize {
        self.len_written()
    }
}

/// Remote suspend response message.
///
/// Reports the suspension state of a transaction after a remote suspend request.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct RemoteSuspendResponseMessage {
    transaction_id: TransactionIdField,
    transaction_status: TransactionStatus,
    suspended: bool,
}

impl RemoteSuspendResponseMessage {
    /// Constructor for the remote suspend response message.
    pub fn new(
        source_entity_id: UnsignedByteField,
        transaction_seq_num: UnsignedByteField,
        transaction_status: TransactionStatus,
        suspended: bool,
    ) -> Result<Self, ReservedMessageCreationError> {
        Ok(Self {
            transaction_id: TransactionIdField::new(source_entity_id, transaction_seq_num)?,
            transaction_status,
            suspended,
        })
    }

    /// Read a remote suspend response message from a raw message to user TLV.
    pub fn from_bytes(buf: &[u8]) -> Result<Self, ReservedMessageReadError> {
        Self::try_from(MsgToUserTlv::from_bytes(buf)?)
    }

    /// Source entity ID of the transaction.
    #[inline]
    pub fn source_entity_id(&self) -> UnsignedByteField {
        self.transaction_id.source_entity_id
    }

    /// Transaction sequence number of the transaction.
    #[inline]
    pub fn transaction_seq_num(&self) -> UnsignedByteField {
        self.transaction_id.transaction_seq_num
    }

    /// Transaction status.
    #[inline]
    pub fn transaction_status(&self) -> TransactionStatus {
        self.transaction_status
    }

    /// Is the transaction suspended?
    #[inline]
    pub fn suspended(&self) -> bool {
        self.suspended
    }

    #[inline]
    fn payload_len(&self) -> usize {
        1 + self.transaction_id.len()
    }

    /// Full written length.
    #[inline]
    pub fn len_written(&self) -> usize {
        MsgToUserTlv::full_len_for_reserved_cfdp_message(self.payload_len())
    }

    /// Write the remote suspend response message into a raw byte buffer.
    ///
    /// Returns the number of bytes written into the provided buffer.
    pub fn write_to_slice(&self, buf: &mut [u8]) -> Result<usize, ByteConversionError> {
        let mut current_index = write_reserved_msg_header(
            buf,
            ReservedMessageType::RemoteSuspendResponse,
            self.payload_len(),
        )?;
        buf[current_index] = write_suspension_status_byte(self.suspended, self.transaction_status);
        current_index += 1;
        Ok(current_index
            + self
                .transaction_id
                .write_to_slice(&mut buf[current_index..])?)
    }

    /// Write the message to an owned [alloc::vec::Vec].
    #[cfg(feature = "alloc")]
    pub fn to_vec(&self) -> alloc::vec::Vec<u8> {
        WritableTlv::to_vec(self)
    }
}

impl TryFrom<MsgToUserTlv<'_>> for RemoteSuspendResponseMessage {
    type Error = ReservedMessageReadError;

    fn try_from(msg_to_user: MsgToUserTlv<'_>) -> Result<Self, Self::Error> {
        let params = msg_to_user.reserved_msg_params(ReservedMessageType::RemoteSuspendResponse)?;
        let (suspended, transaction_status) =
            read_suspension_status_byte(read_single_byte_param(params)?);
        Ok(Self {
            transaction_id: TransactionIdField::from_bytes(&params[1..])?,
            transaction_status,
            suspended,
        })
    }
}

impl WritableTlv for RemoteSuspendResponseMessage {
    fn write_to_slice(&self, buf: &mut [u8]) -> Result<usize, ByteConversionError> {
        self.write_to_slice(buf)
    }

    #[inline]
    fn len_written(&self) -> usize {
        self.len_written()
    }
}

/// Remote resume request message.
///
/// Requests the resumption of a transaction. It must be sent with acknowledged transmission mode.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct RemoteResumeRequestMessage {
    transaction_id: TransactionIdField,
}

impl RemoteResumeRequestMessage {
    /// Constructor for the remote resume request message.
    pub fn new(
        source_entity_id: UnsignedByteField,
        transaction_seq_num: UnsignedByteField,
    ) -> Result<Self, ReservedMessageCreationError> {
        Ok(Self {
            transaction_id: TransactionIdField::new(source_entity_id, transaction_seq_num)?,
        })
    }

    /// Read a remote resume request message from a raw message to user TLV.
    pub fn from_bytes(buf: &[u8]) -> Result<Self, ReservedMessageReadError> {
        Self::try_from(MsgToUserTlv::from_bytes(buf)?)
    }

    /// Source entity ID of the transaction.
    #[inline]
    pub fn source_entity_id(&self) -> UnsignedByteField {
        self.transaction_id.source_entity_id
    }

    /// Transaction sequence number of the transaction.
    #[inline]
    pub fn transaction_seq_num(&self) -> UnsignedByteField {
        self.transaction_id.transaction_seq_num
    }

    /// Full written length.
    #[inline]
    pub fn len_written(&self) -> usize {
        MsgToUserTlv::full_len_for_reserved_cfdp_message(self.transaction_id.len())
    }

    /// Write the remote resume request message into a raw byte buffer.
    ///
    /// Returns the number of bytes written into the provided buffer.
    pub fn write_to_slice(&self, buf: &mut [u8]) -> Result<usize, ByteConversionError> {
        let current_index = write_reserved_msg_header(
            buf,
            ReservedMessageType::RemoteResumeRequest,
            self.transaction_id.len(),
        )?;
        Ok(current_index
            + self
                .transaction_id
                .write_to_slice(&mut buf[current_index..])?)
    }

    /// Write the message to an owned [alloc::vec::Vec].
    #[cfg(feature = "alloc")]
    pub fn to_vec(&self) -> alloc::vec::Vec<u8> {
        WritableTlv::to_vec(self)
    }
}

impl TryFrom<MsgToUserTlv<'_>> for RemoteResumeRequestMessage {
    type Error = ReservedMessageReadError;

    fn try_from(msg_to_user: MsgToUserTlv<'_>) -> Result<Self, Self::Error> {
        let params = msg_to_user.reserved_msg_params(ReservedMessageType::RemoteResumeRequest)?;
        Ok(Self {
            transaction_id: TransactionIdField::from_bytes(params)?,
        })
    }
}

impl WritableTlv for RemoteResumeRequestMessage {
    fn write_to_slice(&self, buf: &mut [u8]) -> Result<usize, ByteConversionError> {
        self.write_to_slice(buf)
    }

    #[inline]
    fn len_written(&self) -> usize {
        self.len_written()
    }
}

/// Remote resume response message.
///
/// Reports the suspension state of a transaction after a remote resume request. The transaction
/// can still be suspended if there are other reasons for the suspension.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct RemoteResumeResponseMessage {
    transaction_id: TransactionIdField,
    transaction_status: TransactionStatus,
    suspended: bool,
}

impl RemoteResumeResponseMessage {
    /// Constructor for the remote resume response message.
    pub fn new(
        source_entity_id: UnsignedByteField,
        transaction_seq_num: UnsignedByteField,
        transaction_status: TransactionStatus,
        suspended: bool,
    ) -> Result<Self, ReservedMessageCreationError> {
        Ok(Self {
            transaction_id: TransactionIdField::new(source_entity_id, transaction_seq_num)?,
            transaction_status,
            suspended,
        })
    }

    /// Read a remote resume response message from a raw message to user TLV.
    pub fn from_bytes(buf: &[u8]) -> Result<Self, ReservedMessageReadError> {
        Self::try_from(MsgToUserTlv::from_bytes(buf)?)
    }

    /// Source entity ID of the transaction.
    #[inline]
    pub fn source_entity_id(&self) -> UnsignedByteField {
        self.transaction_id.source_entity_id
    }

    /// Transaction sequence number of the transaction.
    #[inline]
    pub fn transaction_seq_num(&self) -> UnsignedByteField {
        self.transaction_id.transaction_seq_num
    }

    /// Transaction status.
    #[inline]
    pub fn transaction_status(&self) -> TransactionStatus {
        self.transaction_status
    }

    /// Is the transaction suspended?
    #[inline]
    pub fn suspended(&self) -> bool {
        self.suspended
    }

    #[inline]
    fn payload_len(&self) -> usize {
        1 + self.transaction_id.len()
    }

    /// Full written length.
    #[inline]
    pub fn len_written(&self) -> usize {
        MsgToUserTlv::full_len_for_reserved_cfdp_message(self.payload_len())
    }

    /// Write the remote resume response message into a raw byte buffer.
    ///
    /// Returns the number of bytes written into the provided buffer.
    pub fn write_to_slice(&self, buf: &mut [u8]) -> Result<usize, ByteConversionError> {
        let mut current_index = write_reserved_msg_header(
            buf,
            ReservedMessageType::RemoteResumeResponse,
            self.payload_len(),
        )?;
        buf[current_index] = write_suspension_status_byte(self.suspended, self.transaction_status);
        current_index += 1;
        Ok(current_index
            + self
                .transaction_id
                .write_to_slice(&mut buf[current_index..])?)
    }

    /// Write the message to an owned [alloc::vec::Vec].
    #[cfg(feature = "alloc")]
    pub fn to_vec(&self) -> alloc::vec::Vec<u8> {
        WritableTlv::to_vec(self)
    }
}

impl TryFrom<MsgToUserTlv<'_>> for RemoteResumeResponseMessage {
    type Error = ReservedMessageReadError;

    fn try_from(msg_to_user: MsgToUserTlv<'_>) -> Result<Self, Self::Error> {
        let params = msg_to_user.reserved_msg_params(ReservedMessageType::RemoteResumeResponse)?;
        let (suspended, transaction_status) =
            read_suspension_status_byte(read_single_byte_param(params)?);
        Ok(Self {
            transaction_id: TransactionIdField::from_bytes(&params[1..])?,
            transaction_status,
            suspended,
        })
    }
}

impl WritableTlv for RemoteResumeResponseMessage {
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
    use crate::cfdp::tlv::TlvType;
    use crate::util::UnsignedByteFieldError;

    fn entity_id() -> UnsignedByteField {
        UnsignedByteField::new(2, 0x0102)
    }

    fn seq_num() -> UnsignedByteField {
        UnsignedByteField::new(4, 0x0A0B_0C0D)
    }

    const TRANSACTION_ID_RAW: [u8; 7] = [0b0001_0011, 0x01, 0x02, 0x0A, 0x0B, 0x0C, 0x0D];

    fn remote_status_report_request() -> RemoteStatusReportRequestMessage<'static> {
        RemoteStatusReportRequestMessage::new(
            entity_id(),
            seq_num(),
            Lv::try_from("report.txt").unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn test_remote_status_report_request_serialization() {
        let msg = remote_status_report_request();
        let mut buf: [u8; 32] = [0; 32];
        let written = msg.write_to_slice(&mut buf).unwrap();
        assert_eq!(written, msg.len_written());
        assert_eq!(written, 2 + 4 + 1 + 7 + 11);
        assert_eq!(buf[1] as usize, written - 2);
        assert_eq!(&buf[2..6], b"cfdp");
        assert_eq!(buf[6], 0x20);
        assert_eq!(buf[7..14], TRANSACTION_ID_RAW);
        assert_eq!(buf[14], 10);
        assert_eq!(&buf[15..25], b"report.txt");
    }

    #[test]
    fn test_remote_status_report_request_round_trip() {
        let msg = remote_status_report_request();
        let buf = msg.to_vec();
        let read_back = RemoteStatusReportRequestMessage::from_bytes(&buf).unwrap();
        assert_eq!(read_back, msg);
        assert_eq!(read_back.source_entity_id(), entity_id());
        assert_eq!(read_back.transaction_seq_num(), seq_num());
        assert_eq!(
            read_back.report_file_name().value_as_str(),
            Some(Ok("report.txt"))
        );
    }

    #[test]
    fn test_remote_status_report_request_invalid() {
        assert_eq!(
            RemoteStatusReportRequestMessage::new(
                UnsignedByteField::new(3, 0),
                seq_num(),
                Lv::new_empty()
            ),
            Err(ReservedMessageCreationError::InvalidEntityId(
                UnsignedByteFieldError::InvalidWidth {
                    found: 3,
                    expected: None
                }
            ))
        );
        let name = [b'a'; 245];
        assert!(matches!(
            RemoteStatusReportRequestMessage::new(entity_id(), seq_num(), Lv::new(&name).unwrap()),
            Err(ReservedMessageCreationError::DataTooLarge(_))
        ));
        // The report file name LV is missing.
        let msg_to_user = MsgToUserTlv::new(b"cfdp\x20\x00\x01\x02").unwrap();
        assert!(matches!(
            RemoteStatusReportRequestMessage::try_from(msg_to_user),
            Err(ReservedMessageReadError::ByteConversion(_))
        ));
    }

    #[test]
    fn test_remote_status_report_response_serialization() {
        let msg = RemoteStatusReportResponseMessage::new(
            entity_id(),
            seq_num(),
            TransactionStatus::Terminated,
            true,
        )
        .unwrap();
        let buf = msg.to_vec();
        assert_eq!(buf.len(), msg.len_written());
        assert_eq!(buf[1] as usize, buf.len() - 2);
        assert_eq!(buf[6], 0x21);
        assert_eq!(buf[7], 0b1000_0001);
        assert_eq!(buf[8..], TRANSACTION_ID_RAW);
    }

    #[test]
    fn test_remote_status_report_response_round_trip() {
        for (transaction_status, successful) in [
            (TransactionStatus::Undefined, false),
            (TransactionStatus::Active, true),
            (TransactionStatus::Unrecognized, false),
        ] {
            let msg = RemoteStatusReportResponseMessage::new(
                entity_id(),
                seq_num(),
                transaction_status,
                successful,
            )
            .unwrap();
            let read_back = RemoteStatusReportResponseMessage::from_bytes(&msg.to_vec()).unwrap();
            assert_eq!(read_back, msg);
            assert_eq!(read_back.source_entity_id(), entity_id());
            assert_eq!(read_back.transaction_seq_num(), seq_num());
            assert_eq!(read_back.transaction_status(), transaction_status);
            assert_eq!(read_back.successful(), successful);
        }
    }

    #[test]
    fn test_remote_status_report_response_missing_transaction_id() {
        let msg_to_user = MsgToUserTlv::new(b"cfdp\x21\x81").unwrap();
        assert_eq!(
            RemoteStatusReportResponseMessage::try_from(msg_to_user),
            Err(ReservedMessageReadError::ByteConversion(
                ByteConversionError::FromSliceTooSmall {
                    found: 0,
                    expected: 1
                }
            ))
        );
    }

    #[test]
    fn test_remote_suspend_and_resume_request_serialization() {
        let suspend = RemoteSuspendRequestMessage::new(entity_id(), seq_num()).unwrap();
        let resume = RemoteResumeRequestMessage::new(entity_id(), seq_num()).unwrap();
        for (buf, msg_type) in [(suspend.to_vec(), 0x30), (resume.to_vec(), 0x38)] {
            assert_eq!(buf.len(), 2 + 4 + 1 + 7);
            assert_eq!(buf[0], TlvType::MsgToUser as u8);
            assert_eq!(buf[1] as usize, buf.len() - 2);
            assert_eq!(&buf[2..6], b"cfdp");
            assert_eq!(buf[6], msg_type);
            assert_eq!(buf[7..], TRANSACTION_ID_RAW);
        }
        assert_eq!(suspend.len_written(), suspend.to_vec().len());
        assert_eq!(resume.len_written(), resume.to_vec().len());
    }

    #[test]
    fn test_remote_suspend_and_resume_request_round_trip() {
        let suspend = RemoteSuspendRequestMessage::new(entity_id(), seq_num()).unwrap();
        let read_back = RemoteSuspendRequestMessage::from_bytes(&suspend.to_vec()).unwrap();
        assert_eq!(read_back, suspend);
        assert_eq!(read_back.source_entity_id(), entity_id());
        assert_eq!(read_back.transaction_seq_num(), seq_num());

        let resume = RemoteResumeRequestMessage::new(entity_id(), seq_num()).unwrap();
        let read_back = RemoteResumeRequestMessage::from_bytes(&resume.to_vec()).unwrap();
        assert_eq!(read_back, resume);
        assert_eq!(read_back.source_entity_id(), entity_id());
        assert_eq!(read_back.transaction_seq_num(), seq_num());

        assert_eq!(
            RemoteResumeRequestMessage::from_bytes(&suspend.to_vec()),
            Err(ReservedMessageReadError::UnexpectedMessageType {
                found: ReservedMessageType::RemoteSuspendRequest,
                expected: ReservedMessageType::RemoteResumeRequest,
            })
        );
    }

    #[test]
    fn test_remote_suspend_request_invalid_seq_num_width() {
        assert_eq!(
            RemoteSuspendRequestMessage::new(entity_id(), UnsignedByteField::new(5, 0)),
            Err(ReservedMessageCreationError::InvalidTransactionSeqNum(
                UnsignedByteFieldError::InvalidWidth {
                    found: 5,
                    expected: None
                }
            ))
        );
    }

    #[test]
    fn test_remote_suspend_and_resume_response_serialization() {
        let suspend = RemoteSuspendResponseMessage::new(
            entity_id(),
            seq_num(),
            TransactionStatus::Active,
            true,
        )
        .unwrap();
        let resume = RemoteResumeResponseMessage::new(
            entity_id(),
            seq_num(),
            TransactionStatus::Unrecognized,
            false,
        )
        .unwrap();
        for (buf, msg_type, status) in [
            (suspend.to_vec(), 0x31, 0b1010_0000),
            (resume.to_vec(), 0x39, 0b0110_0000),
        ] {
            assert_eq!(buf.len(), 2 + 4 + 1 + 1 + 7);
            assert_eq!(buf[1] as usize, buf.len() - 2);
            assert_eq!(buf[6], msg_type);
            assert_eq!(buf[7], status);
            assert_eq!(buf[8..], TRANSACTION_ID_RAW);
        }
        assert_eq!(suspend.len_written(), suspend.to_vec().len());
        assert_eq!(resume.len_written(), resume.to_vec().len());
    }

    #[test]
    fn test_remote_suspend_and_resume_response_round_trip() {
        for (transaction_status, suspended) in [
            (TransactionStatus::Active, true),
            (TransactionStatus::Terminated, false),
        ] {
            let suspend = RemoteSuspendResponseMessage::new(
                entity_id(),
                seq_num(),
                transaction_status,
                suspended,
            )
            .unwrap();
            let read_back = RemoteSuspendResponseMessage::from_bytes(&suspend.to_vec()).unwrap();
            assert_eq!(read_back, suspend);
            assert_eq!(read_back.source_entity_id(), entity_id());
            assert_eq!(read_back.transaction_seq_num(), seq_num());
            assert_eq!(read_back.transaction_status(), transaction_status);
            assert_eq!(read_back.suspended(), suspended);

            let resume = RemoteResumeResponseMessage::new(
                entity_id(),
                seq_num(),
                transaction_status,
                suspended,
            )
            .unwrap();
            let read_back = RemoteResumeResponseMessage::from_bytes(&resume.to_vec()).unwrap();
            assert_eq!(read_back, resume);
            assert_eq!(read_back.transaction_status(), transaction_status);
            assert_eq!(read_back.suspended(), suspended);
        }
    }

    #[test]
    fn test_remote_suspend_response_spare_bits_ignored() {
        let msg_to_user = MsgToUserTlv::new(b"cfdp\x31\x1f\x00\x01\x02").unwrap();
        let msg = RemoteSuspendResponseMessage::try_from(msg_to_user).unwrap();
        assert!(!msg.suspended());
        assert_eq!(msg.transaction_status(), TransactionStatus::Undefined);
        assert_eq!(msg.source_entity_id(), UnsignedByteField::new(1, 1));
        assert_eq!(msg.transaction_seq_num(), UnsignedByteField::new(1, 2));
    }

    #[test]
    fn test_remote_messages_writable_tlv_impls() {
        let mut buf: [u8; 64] = [0; 64];
        let messages: [&dyn WritableTlv; 6] = [
            &remote_status_report_request(),
            &RemoteStatusReportResponseMessage::new(
                entity_id(),
                seq_num(),
                TransactionStatus::Active,
                true,
            )
            .unwrap(),
            &RemoteSuspendRequestMessage::new(entity_id(), seq_num()).unwrap(),
            &RemoteSuspendResponseMessage::new(
                entity_id(),
                seq_num(),
                TransactionStatus::Active,
                true,
            )
            .unwrap(),
            &RemoteResumeRequestMessage::new(entity_id(), seq_num()).unwrap(),
            &RemoteResumeResponseMessage::new(
                entity_id(),
                seq_num(),
                TransactionStatus::Active,
                false,
            )
            .unwrap(),
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
