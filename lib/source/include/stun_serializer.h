#ifndef STUN_SERIALIZER_H
#define STUN_SERIALIZER_H

#include "stun_data_types.h"

StunResult_t StunSerializer_Init( StunContext_t * pCtx,
                                  uint8_t * pBuffer,
                                  size_t bufferLength,
                                  const StunHeader_t * pHeader );

StunResult_t StunSerializer_AddAttributePriority( StunContext_t * pCtx,
                                                  uint32_t priority );

StunResult_t StunSerializer_AddAttributeFingerprint( StunContext_t * pCtx,
                                                     uint32_t crc32Fingerprint );

StunResult_t StunSerializer_AddAttributeLifetime( StunContext_t * pCtx,
                                                  uint32_t lifetime );

StunResult_t StunSerializer_AddAttributeUsername( StunContext_t * pCtx,
                                                  const char * pUsername,
                                                  uint16_t usernameLength );

StunResult_t StunSerializer_AddAttributeAddress( StunContext_t * pCtx,
                                                 StunAttributeAddress_t *pstunMappedAddress );

StunResult_t StunSerializer_AddAttributeXORAddress( StunContext_t * pCtx,
                                                    StunAttributeAddress_t *pstunMappedAddress,
                                                    uint8_t * transactionId );

/* StunSerializer_AddAttributeFingerprint,
 * StunSerializer_AddAttributeIntegrity,
 * StunSerializer_AddAttributeRealm,
 * StunSerializer_AddAttributeNonce,
 *  ... */

StunResult_t StunSerializer_Finalize( StunContext_t * pCtx,
                                      const uint8_t ** pStunMessage,
                                      size_t * pStunMessageLength );

#endif /* STUN_SERIALIZER_H */
