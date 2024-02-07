
#ifndef STUN_DESERIALIZER_H
#define STUN_DESERIALIZER_H

#include "stun_data_types.h"

StunResult_t StunDeserializer_Init( StunContext_t * pCtx,
                                    const uint8_t * pStunMessage,
                                    size_t stunMessageLength,
                                    StunHeader_t * pStunHeader );

StunResult_t StunDeserializer_GetNextAttribute( StunContext_t * pCtx,
                                                StunAttribute_t * pAttribute );

StunResult_t StunDeserializer_ParseAttributePriority( const StunAttribute_t * pAttribute,
                                                      uint32_t * pPriority );

StunResult_t StunDeserializer_ParseAttributeFingerpint( const StunAttribute_t * pAttribute,
                                                        uint32_t * crc32Fingerprint );

StunResult_t StunDeserializer_ParseAttributeLifetime( const StunAttribute_t * pAttribute,
                                                      uint32_t * lifetime );

StunResult_t StunDeserializer_ParseAttributeChangeRequest( const StunAttribute_t * pAttribute,
                                                        uint32_t * pChangeFlag );

StunResult_t StunDeserializer_ParseAttributeIceControlled( const StunAttribute_t * pAttribute,
                                                           uint64_t * pTieBreaker );

StunResult_t StunDeserializer_ParseAttributeIceControlling( const StunAttribute_t * pAttribute,
                                                            uint64_t * pTieBreaker );

StunResult_t StunDeserializer_ParseAttributeUsername( const StunAttribute_t * pAttribute,
                                                      const char ** pUsername,
                                                      uint16_t * pUsernameLength );

StunResult_t StunDeserializer_ParseAttributeData( const StunAttribute_t * pAttribute,
                                                      const char ** pData,
                                                      uint16_t * pDataLength );

StunResult_t StunDeserializer_ParseAttributeRealm( const StunAttribute_t * pAttribute,
                                                   const char ** pRealm,
                                                   uint16_t * pRealmLength );

StunResult_t StunDeserializer_ParseAttributeNonce( const StunAttribute_t * pAttribute,
                                                   const char ** pNonce,
                                                   uint16_t * pNonceLength );

StunResult_t StunDeserializer_ParseAttributeRequestedTransport( const StunAttribute_t * pAttribute,
                                                                const char ** pRequestedTransport,
                                                                uint16_t * pRequestedTransportLength );

StunResult_t StunDeserializer_ParseAttributeIntegrity( const StunAttribute_t * pAttribute,
                                                       const char ** pIntegrity,
                                                       uint16_t * pIntegrityLength );

StunResult_t StunDeserializer_ParseAttributeMappedAddress( const StunAttribute_t * pAttribute,
                                                           StunAttributeAddress_t *pStunMappedAddress );

StunResult_t StunDeserializer_ParseAttributeResponseAddress( const StunAttribute_t * pAttribute,
                                                           StunAttributeAddress_t *pStunMappedAddress );

StunResult_t StunDeserializer_ParseAttributeSourceAddress( const StunAttribute_t * pAttribute,
                                                           StunAttributeAddress_t *pStunMappedAddress );

StunResult_t StunDeserializer_ParseAttributeChangedAddress( const StunAttribute_t * pAttribute,
                                                            StunAttributeAddress_t *pStunMappedAddress );

StunResult_t StunDeserializer_ParseAttributeReflectedFrom( const StunAttribute_t * pAttribute,
                                                           StunAttributeAddress_t *pStunMappedAddress );

StunResult_t StunDeserializer_ParseAttributeXORMappedAddress( const StunAttribute_t * pAttribute,
                                                              StunAttributeAddress_t *pStunMappedAddress,
                                                              uint8_t *pTransactionId );

StunResult_t StunDeserializer_ParseAttributeXORPeerAddress( const StunAttribute_t * pAttribute,
                                                            StunAttributeAddress_t *pStunMappedAddress,
                                                            uint8_t *pTransactionId );

StunResult_t StunDeserializer_ParseAttributeXORRelayedAddress( const StunAttribute_t * pAttribute,
                                                               StunAttributeAddress_t *pStunMappedAddress,
                                                               uint8_t *pTransactionId );

StunResult_t StunDeserializer_ParseAttributeErrorCode( const StunAttribute_t * pAttribute,
                                                       uint16_t * errorCode,
                                                       uint8_t ** errorPhrase );

StunResult_t StunDeserializer_ParseAttributeChannelNumber( const StunAttribute_t * pAttribute,
                                                           uint16_t * channelNumber,
                                                           StunAttributeType_t attributeType );

StunResult_t StunDeserializer_ParseAttributeDontFragment( StunContext_t * pCtx,
                                                          const StunAttribute_t * pAttribute,
                                                          StunAttributeType_t attributeType );

StunResult_t StunDeserializer_ParseAttributeUseCandidate( StunContext_t * pCtx,
                                                          const StunAttribute_t * pAttribute,
                                                          StunAttributeType_t attributeType );

StunResult_t StunDeserializer_IsFlagAttributeFound( const StunContext_t * pCtx,
                                                    StunAttributeType_t attributeType,
                                                    uint16_t * attrFound );

StunResult_t StunDeserializer_GetIntegrityBuffer( StunContext_t * pCtx,
                                                uint8_t ** ppStunMessage,
                                                uint16_t * pStunMessageLength );

StunResult_t StunDeserializer_GetFingerprintBuffer( StunContext_t * pCtx,
                                                  uint8_t ** ppStunMessage,
                                                  uint16_t * pStunMessageLength );
#endif /* STUN_DESERIALIZER_H */
