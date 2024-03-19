
#ifndef STUN_DESERIALIZER_H
#define STUN_DESERIALIZER_H

#include "stun_data_types.h"

StunResult_t StunDeserializer_Init( StunContext_t * pCtx,
                                    const uint8_t * pStunMessage,
                                    size_t stunMessageLength,
                                    StunHeader_t * pStunHeader );

StunResult_t StunDeserializer_GetNextAttribute( StunContext_t * pCtx,
                                                StunAttribute_t * pAttribute );

StunResult_t StunDeserializer_ParseAttributeErrorCode( const StunAttribute_t * pAttribute,
                                                       uint16_t * pErrorCode,
                                                       uint8_t ** ppErrorPhrase,
                                                       uint16_t * pErrorPhraseLength );

StunResult_t StunDeserializer_ParseAttributeChannelNumber( const StunContext_t * pCtx,
                                                           const StunAttribute_t * pAttribute,
                                                           uint16_t * pChannelNumber );

StunResult_t StunDeserializer_ParseAttributePriority( const StunContext_t * pCtx,
                                                      const StunAttribute_t * pAttribute,
                                                      uint32_t * pPriority );

StunResult_t StunDeserializer_ParseAttributeFingerprint( const StunContext_t * pCtx,
                                                         const StunAttribute_t * pAttribute,
                                                         uint32_t * pCrc32Fingerprint );

StunResult_t StunDeserializer_ParseAttributeLifetime( const StunContext_t * pCtx,
                                                      const StunAttribute_t * pAttribute,
                                                      uint32_t * pLifetime );

StunResult_t StunDeserializer_ParseAttributeChangeRequest( const StunContext_t * pCtx,
                                                           const StunAttribute_t * pAttribute,
                                                           uint32_t * pChangeFlag );

StunResult_t StunDeserializer_ParseAttributeIceControlled( const StunContext_t * pCtx,
                                                           const StunAttribute_t * pAttribute,
                                                           uint64_t * pIceControlledValue );

StunResult_t StunDeserializer_ParseAttributeIceControlling( const StunContext_t * pCtx,
                                                            const StunAttribute_t * pAttribute,
                                                            uint64_t * pIceControllingValue );

StunResult_t StunDeserializer_ParseAttributeAddress( const StunContext_t * pCtx,
                                                     const StunAttribute_t * pAttribute,
                                                     StunAttributeAddress_t * pAddress,
                                                     StunAttributeType_t attributeType );

StunResult_t StunDeserializer_ParseAttributeMappedAddress( const StunContext_t * pCtx,
                                                           const StunAttribute_t * pAttribute,
                                                           StunAttributeAddress_t * pMappedAddress );

StunResult_t StunDeserializer_ParseAttributeResponseAddress( const StunContext_t * pCtx,
                                                             const StunAttribute_t * pAttribute,
                                                             StunAttributeAddress_t * pResponseAddress );

StunResult_t StunDeserializer_ParseAttributeSourceAddress( const StunContext_t * pCtx,
                                                           const StunAttribute_t * pAttribute,
                                                           StunAttributeAddress_t * pSourceAddress );

StunResult_t StunDeserializer_ParseAttributeChangedAddress( const StunContext_t * pCtx,
                                                            const StunAttribute_t * pAttribute,
                                                            StunAttributeAddress_t * pChangedAddress );

StunResult_t StunDeserializer_ParseAttributeReflectedFrom( const StunContext_t * pCtx,
                                                           const StunAttribute_t * pAttribute,
                                                           StunAttributeAddress_t * pReflectedFromAddress );

StunResult_t StunDeserializer_ParseAttributeXORMappedAddress( const StunContext_t * pCtx,
                                                              const StunAttribute_t * pAttribute,
                                                              StunAttributeAddress_t * pMappedAddress );

StunResult_t StunDeserializer_ParseAttributeXORPeerAddress( const StunContext_t * pCtx,
                                                            const StunAttribute_t * pAttribute,
                                                            StunAttributeAddress_t * pPeerAddress );

StunResult_t StunDeserializer_ParseAttributeXORRelayedAddress( const StunContext_t * pCtx,
                                                               const StunAttribute_t * pAttribute,
                                                               StunAttributeAddress_t * pRelayedAddress );

StunResult_t StunDeserializer_GetIntegrityBuffer( StunContext_t * pCtx,
                                                  uint8_t ** ppStunMessage,
                                                  uint16_t * pStunMessageLength );

StunResult_t StunDeserializer_GetFingerprintBuffer( StunContext_t * pCtx,
                                                    uint8_t ** ppStunMessage,
                                                    uint16_t * pStunMessageLength );

StunResult_t StunDeserializer_FindAttribute( StunContext_t * pCtx,
                                             StunAttributeType_t attributeType,
                                             StunAttribute_t * pAttribute );

StunResult_t StunDeserializer_UpdateAttributeNonce( const StunContext_t * pCtx,
                                                    const char * pNonce,
                                                    uint16_t nonceLength,
                                                    StunAttribute_t * pAttribute );

#endif /* STUN_DESERIALIZER_H */
