//Source: https://github.com/vmware/likewise-open/blob/d6511c1389f84e178520c844451885be360c2d9b/lwio/server/include/smbwire.h

NTSTATUS WireMarshallTransactionSecondaryResponseData(
    uint8_t  *pBuffer,
    uint32_t  bufferLen,
    uint32_t *pBufferUsed,
    uint16_t *pSetup,
    uint8_t   setupLen,
    uint8_t  *pParameters,
    uint32_t  parameterLen,
    uint16_t *pParameterOffset,
    uint8_t  *pData,
    uint32_t  dataLen,
    uint16_t *pDataOffset
    );

NTSTATUS WireUnmarshallTransactionSecondaryResponse(
    const PBYTE pBuffer,
    ULONG       ulNumBytesAvailable,
    ULONG       ulOffset,
    PTRANSACTION_SECONDARY_RESPONSE_HEADER* ppHeader,
    PUSHORT*    ppSetup,
    PUSHORT*    ppByteCount,
    PWSTR*      ppwszName,
    PBYTE*      ppParameters,
    PBYTE*      ppData,
    USHORT      dataLen
    );

NTSTATUS WreMarshallTransaction2Response(
    PBYTE       pBuffer,
    ULONG       ulNumBytesAvailable,
    ULONG       ulOffset,
    PUSHORT     pSetup,
    BYTE        setupCount,
    PBYTE       pParams,
    USHORT      usParamLength,
    PBYTE       pData,
    USHORT      usDataLen,
    PUSHORT     pusDataOffset,
    PUSHORT     pusParameterOffset,
    PUSHORT     pusNumPackageBytesUsed
    );
    
    
  /**
 * @brief Marshal setup portion of trans2 request
 *
 * Marshals the setup portion of a trans2 request and
 * returns pointers to areas that need to be filled in.
 *
 * @param[in, out] pSmbHeader a pointer to the SMB header in the packet.
 * This is used as a reference point for alignment.  Upon return, the
 * WordCount field will be set to the correct value for the request.
 * @param[in,out] ppCursor the data cursor.  Upon call it must point
 * to the parameters portion of the SMB packet.  Upon return
 * it will point to the beginning of the trans2 parameters
 * block.
 * @param[in,out] pulRemainingSpace remaining space in the buffer.  Upon
 * call it should contain the number of bytes of space available
 * after the cursor.  Upon return it will be updated to reflect
 * how much space is left.
 * @param[in] pusSetupWords a pointer to the setup words
 * @param[in] usSetupWordCount the number of setup words
 * @param[out] ppRequestHeader the static portion of the request
 * @param[out] ppByteCount the location of the byte count field
 *
 * @return an NT status code
 * @retval STATUS_SUCCESS success
 * @retval STATUS_BUFFER_TOO_SMALL the remaining space was exceeded during marshaling
 */
NTSTATUS WireMarshalTrans2RequestSetup(
    IN OUT PSMB_HEADER               pSmbHeader,
    IN OUT PBYTE*                    ppCursor,
    IN OUT PULONG                    pulRemainingSpace,
    IN PUSHORT                       pusSetupWords,
    IN USHORT                        usSetupWordCount,
    OUT PTRANSACTION_REQUEST_HEADER* ppRequestHeader,
    OUT PBYTE*                       ppByteCount
    );

/**
 * @brief Unmarshal setup portion of trans2 response
 *
 * Unmarshals the setup portion of a trans2 request and
 * returns pointers to the segments of interest within
 * the packet.
 *
 * @param[in] pSmbHeader a pointer to the SMB header in the packet.
 * This is used as a reference point for alignment.
 * @param[in,out] ppCursor the data cursor.  Upon call it must point
 * to the parameters portion of the SMB packet.  Upon return
 * it will point exactly past the end of the trans2 reponse.
 * @param[in,out] pulRemainingSpace remaining space in the buffer.  Upon
 * call it should contain the number of bytes of space available
 * after the cursor.  Upon return it will be updated to reflect
 * how much space is left.
 * @param[optional,out] ppResponseHeader a pointer to the static portion of the
 * response header.
 * @param[optional,out] ppusSetupWords a pointer to the setup words in the response
 * @param[optional,out] pusSetupWordCount the number of setup words in the response
 * @param[optional,out] pusByteCount the number of total bytes in the response
 * after the setup words
 * @param[optional,out] ppParamterBlock a pointer to the start of the parameter block
 * @param[optional,out] ppDataBlock a pointer to the start of the data block
 *
 * @return an NT status code
 * @retval STATUS_SUCCESS success
 * @retval STATUS_BUFFER_TOO_SMALL the remaining space was exceeded during marshaling
 */
NTSTATUS WireUnmarshalTrans2ReplySetup(
    IN PSMB_HEADER                                        pSmbHeader,
    IN OUT PBYTE*                                         ppCursor,
    IN OUT PULONG                                         pulRemainingSpace,
    OPTIONAL OUT PTRANSACTION_SECONDARY_RESPONSE_HEADER*  ppResponseHeader,
    OPTIONAL OUT PUSHORT                                  pusTotalParameterCount,
    OPTIONAL OUT PUSHORT                                  pusTotalDataCount,
    OPTIONAL OUT PUSHORT*                                 ppusSetupWords,
    OPTIONAL OUT PUSHORT                                  pusSetupWordCount,
    OPTIONAL OUT PUSHORT                                  pusByteCount,
    OPTIONAL OUT PBYTE*                                   ppParameterBlock,
    OPTIONAL OUT PUSHORT                                  pusParameterCount,
    OPTIONAL OUT PBYTE*                                   ppDataBlock,
    OPTIONAL OUT PUSHORT                                  pusDataCount
    );  
