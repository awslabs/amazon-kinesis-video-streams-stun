#ifndef STUN_SERIALIZER_H
#define STUN_SERIALIZER_H

#include "stun_data_types.h"

StunResult_t StunSerializer_Init( StunContext_t * pCtx,
                                  uint8_t * pBuffer,
                                  size_t bufferLength,
                                  const StunHeader_t * pHeader );

StunResult_t StunSerializer_AddAttributeErrorCode( StunContext_t * pCtx,
                                                   uint16_t errorCode,
                                                   const uint8_t * pErrorPhrase,
                                                   uint16_t errorPhraseLength );

StunResult_t StunSerializer_AddAttributeChannelNumber( StunContext_t * pCtx,
                                                       uint16_t channelNumber );

StunResult_t StunSerializer_AddAttributeUseCandidate( StunContext_t * pCtx );

StunResult_t StunSerializer_AddAttributeDontFragment( StunContext_t * pCtx );

StunResult_t StunSerializer_AddAttributePriority( StunContext_t * pCtx,
                                                  uint32_t priority );

StunResult_t StunSerializer_AddAttributeFingerprint( StunContext_t * pCtx,
                                                     uint32_t crc32Fingerprint );

StunResult_t StunSerializer_AddAttributeLifetime( StunContext_t * pCtx,
                                                  uint32_t lifetime );

StunResult_t StunSerializer_AddAttributeChangeRequest( StunContext_t * pCtx,
                                                       uint32_t changeFlag );

StunResult_t StunSerializer_AddAttributeIceControlled( StunContext_t * pCtx,
                                                       uint64_t tieBreaker );

StunResult_t StunSerializer_AddAttributeIceControlling( StunContext_t * pCtx,
                                                        uint64_t tieBreaker );

StunResult_t StunSerializer_AddAttributeUsername( StunContext_t * pCtx,
                                                  const uint8_t * pUsername,
                                                  uint16_t usernameLength );

StunResult_t StunSerializer_AddAttributeData( StunContext_t * pCtx,
                                              const uint8_t * pData,
                                              uint16_t dataLength );

StunResult_t StunSerializer_AddAttributeRealm( StunContext_t * pCtx,
                                               const uint8_t * pRealm,
                                               uint16_t realmLength );

StunResult_t StunSerializer_AddAttributeNonce( StunContext_t * pCtx,
                                               const uint8_t * pNonce,
                                               uint16_t nonceLength );

StunResult_t StunSerializer_AddAttributeRequestedTransport( StunContext_t * pCtx,
                                                            const uint8_t * pRequestedTransport,
                                                            uint16_t requestedTransportLength );

StunResult_t StunSerializer_AddAttributeIntegrity( StunContext_t * pCtx,
                                                   const uint8_t * pIntegrity,
                                                   uint16_t integrityLength );

StunResult_t StunSerializer_AddAttributeAddress( StunContext_t * pCtx,
                                                 StunAttributeAddress_t * pAddress,
                                                 StunAttributeType_t attributeType );

StunResult_t StunSerializer_AddAttributeMappedAddress( StunContext_t * pCtx,
                                                       StunAttributeAddress_t * pMappedAddress );

StunResult_t StunSerializer_AddAttributeResponseAddress( StunContext_t * pCtx,
                                                         StunAttributeAddress_t * pResponseAddress );

StunResult_t StunSerializer_AddAttributeSourceAddress( StunContext_t * pCtx,
                                                       StunAttributeAddress_t * pSourceAddress );

StunResult_t StunSerializer_AddAttributeChangedAddress( StunContext_t * pCtx,
                                                        StunAttributeAddress_t * pChangedAddress );

StunResult_t StunSerializer_AddAttributeChangedReflectedFrom( StunContext_t * pCtx,
                                                              StunAttributeAddress_t * pReflectedFromAddress );

StunResult_t StunSerializer_AddAttributeXorMappedAddress( StunContext_t * pCtx,
                                                          StunAttributeAddress_t * pMappedAddress );

StunResult_t StunSerializer_AddAttributeXorPeerAddress( StunContext_t * pCtx,
                                                        StunAttributeAddress_t * pPeerAddress );

StunResult_t StunSerializer_AddAttributeXorRelayedAddress( StunContext_t * pCtx,
                                                           StunAttributeAddress_t * pRelayedAddress );

StunResult_t StunSerializer_GetIntegrityBuffer( StunContext_t * pCtx,
                                                uint8_t ** ppStunMessage,
                                                uint16_t * pStunMessageLength );

StunResult_t StunSerializer_GetFingerprintBuffer( StunContext_t * pCtx,
                                                  uint8_t ** ppStunMessage,
                                                  uint16_t * pStunMessageLength );

StunResult_t StunSerializer_Finalize( StunContext_t * pCtx,
                                      uint32_t * pStunMessageLength );

#endif /* STUN_SERIALIZER_H */
